
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;


public class SeiTchiz {

	public static void main(String[] args)  {

		if(args.length !=5) {
			throw new IllegalArgumentException("Wrong program arguments!\nHow to run example: SeiTchiz <serverAddress> <truststore> <keystore> <keystore-password> <clientID>");
		}

		String trustStore=args[1];
		String kstore=args[2];
		String ksPassword=args[3];
		String clientID = args[4]; 
		System.setProperty("javax.net.ssl.trustStore",trustStore);
		String serverAddress = args[0]; 
		SSLSocket clientSocket= null;

		try {

			SocketFactory ssf= SSLSocketFactory.getDefault();
			String[] ipAndPort=serverAddress.split(":");
			if(ipAndPort.length==1)
				clientSocket=  (SSLSocket) ssf.createSocket(serverAddress, 45678);
			else
				clientSocket= (SSLSocket) ssf.createSocket(ipAndPort[0], Integer.parseInt(ipAndPort[1]));


		} catch(IOException e) {
			System.err.println(e.getMessage());
			System.exit(1);
		}

		boolean authenticated = false;
		boolean finished = false;



		if(clientID.contains(",")|| clientID.contains(":")) {
			throw new IllegalArgumentException("Your ClientID contains illegal characters");
		}

		Scanner scanner = new Scanner(System.in);

		try {

			ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
			ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
			SSLSession sess = clientSocket.getSession( );
			String host = sess.getPeerHost( );

			out.writeObject(clientID);
			out.flush();

			byte[] nonce = new byte[8];


			in.readFully(nonce,0,8);

			int authFlag =in.readInt();

			KeyStore ks	= KeyStore.getInstance("JCEKS");
			FileInputStream keyIS = new FileInputStream(kstore);
			ks.load(keyIS, ksPassword.toCharArray());
			Enumeration<String> aliases = ks.aliases();
			String alias = aliases.nextElement();
			Key privateKey = ks.getKey(alias, ksPassword.toCharArray());
			Certificate certificate= ks.getCertificate(alias);

			Cipher c = Cipher.getInstance("RSA");
			c.init(Cipher.ENCRYPT_MODE, privateKey);
			byte[] enc = c.doFinal(nonce);
			int encSize=enc.length;

			if(authFlag==0) {

				out.write(nonce);
				out.flush();
				out.writeInt(encSize); //Envia o tamanho do nonce encriptado
				out.flush();
				out.write(enc,0,encSize);
				out.flush();
				out.writeObject(certificate);




			} 

			else if(authFlag==1) {
				out.writeInt(encSize); //Envia o tamanho do nonce encriptado
				out.flush();
				out.write(enc,0,encSize);
				out.flush();				
			}


			String authenti_reply = "";
			authenti_reply = (String) in.readObject();

			if (authenti_reply.equals("Error")) {
				System.out.println("Error: Invalid credentials, client is shutting down");
				System.exit(1);
			}else if (authenti_reply.equals("NoSuchClientID")){
				System.out.println("Vamos registar a conta com o seu id e a sua chave pública.");
				authenticated=true;

			}

			if (authenti_reply.equals("Success")) {
				authenticated = true;
			}

			System.out.println("Succesful Login: " + authenticated);
			if(authenticated)
				showMenu();


			while(!finished) {
				System.out.println("\nInsira um comando!");
				String command = scanner.nextLine();
				if (command.equals("quit")) {
					finished = true;
				}else {
					boolean success = sendRequest(command, out, in, clientID, kstore, ksPassword);
					if (success) {
						out.flush();
						String serverReply = (String) in.readObject();
						System.out.println(serverReply);
					}else {
						System.out.println("Erro: Comando inválido.");
					}

				}

			}

			scanner.close();
			in.close();
			out.close();
			clientSocket.close();


		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			//System.out.println("Adeus!");
		} 




		System.out.println("You have logged out.");

	}

	private static void showMenu() {
		System.out.println("Eis os comandos disponíveis: ");
		System.out.println("- follow <userID> | f <userID>");
		System.out.println("- unfollow <userID> | u <userID>");
		System.out.println("- viewfollowers | v");
		System.out.println("- wall <nPhotos> | w <nPhotos>");
		System.out.println("- like <photoID> | l <photoID>");
		System.out.println("- newgroup <groupID> | n <groupID>");
		System.out.println("- addu <userID> <groupID> | a <userID> <groupID>");
		System.out.println("- removeu <userID> <groupID> | r <userID> <groupID>");
		System.out.println("- ginfo [groupID] | g [groupID]");
		System.out.println("- msg <groupID><msg> | m <groupID><msg>");
		System.out.println("- collect <groupID> | c <groupID>");
		System.out.println("- history <groupID> | h <groupID>");
		System.out.println("- quit");
	}

	public static boolean sendRequest (String command, ObjectOutputStream out, ObjectInputStream in, String clientID, String ks, String ksPassword) {
		List<String> full_command = new ArrayList<String>(Arrays.asList(command.split(" ")));
		String command_type = full_command.get(0).toLowerCase();
		full_command.remove(0);

		try {

			if (command_type.equals("follow") || command_type.equals("f")) {

				if (full_command.size() == 1) {
					out.writeObject("f");
					String args_string = "";
					for (String s : full_command) {
						args_string += s;
					}
					out.writeObject(args_string);
					return true;	
				}


			} else if (command_type.equals("unfollow") || command_type.equals("u")){

				if (full_command.size() == 1) {
					out.writeObject("u");
					String args_string = "";
					for (String s : full_command) {
						args_string += s;
					}
					out.writeObject(args_string);
					return true;	
				}


			} else if (command_type.equals("viewfollowers") || command_type.equals("v")){

				if (full_command.size() == 0) {
					out.writeObject("v");
					return true;
				}

			} else if (command_type.equals("post") || command_type.equals("p")) {

				if(full_command.size() >= 1) {
					String path="";

					for(int i=0; i<full_command.size();i++) {
						if(i==full_command.size()-1)
							path+=full_command.get(i);
						else
							path+=full_command.get(i)+" ";
					}

					File photoFile = new File(path);

					if(photoFile.exists()) {

						out.writeObject("p");
						out.flush();

						FileInputStream photoFIS = new FileInputStream(photoFile);
						InputStream inStream = new BufferedInputStream(photoFIS);

						int fileSize = (int) photoFile.length();
						byte[] photoInBytes = new byte[fileSize];

						inStream.read(photoInBytes);

						out.writeInt(fileSize);
						out.flush();

						out.write(photoInBytes, 0, fileSize);
						out.flush();
						inStream.close();
						return true;
					}
					System.out.println("That file does not exist!");
				}

			} else if (command_type.equals("like") || command_type.equals("l")) {

				if(full_command.size() == 1) {
					out.writeObject("l");
					out.flush();
					out.writeObject(full_command.get(0));
					out.flush();
					return true;
				}

			} else if(command_type.equals("wall") || command_type.equals("w")) {

				if(full_command.size() == 1) {
					int wallNPhotos = 0 ;
					try {
						wallNPhotos = Integer.parseInt(full_command.get(0));
					}catch (NumberFormatException e) {
						System.out.println("Invalid use of wall!");
						return false;
					}
					out.writeObject("w");
					out.flush();
					out.writeInt(wallNPhotos);
					out.flush();

					int nPhotos = in.readInt();

					if(nPhotos != -1) {


						System.out.println("Wall:");
						for(int i=0; i < nPhotos ; i++) {

							String fileName=(String)in.readObject();
							String peopleWhoLiked=(String)in.readObject();

							int wasPhotoCorrupted=in.readInt();
							String filePath =  "client_" + fileName+ ".jpg";
							if(wasPhotoCorrupted==1) {
								int fileSize = in.readInt();

								byte [] fileBuffer= new byte[fileSize];
								in.readFully(fileBuffer, 0, fileSize);

								//alterado
								File photos=new File("photos_"+clientID);
								if(!photos.exists())
									photos.mkdir();
								File fileReceived = new File("photos_"+clientID+File.separator+filePath);
								FileOutputStream fos;
								fos = new FileOutputStream(fileReceived);

								OutputStream output = new BufferedOutputStream(fos);
								output.write(fileBuffer);

								System.out.println("Photo: " + fileName);
								String[]likes_copy=peopleWhoLiked.split(",").clone();							

								if(!peopleWhoLiked.equals("null"))
									System.out.println("Likes na foto: "+ likes_copy.length+ " de: " +peopleWhoLiked);
								else
									System.out.println("Likes na foto: 0");

								output.close();
								fos.close();
							}
							else {
								System.out.println("Photo " +filePath+ " was corrupted");
							}
						}
					}
					return true;

				}

			} else if(command_type.equals("newgroup") || command_type.equals("n")) {

				if(full_command.size() == 1) {

					out.writeObject("n");
					String groupID = full_command.get(0);

					KeyGenerator keyGen;
					keyGen = KeyGenerator.getInstance("AES");
					keyGen.init(128);
					Key secretKey = keyGen.generateKey();

					byte[] ciphGroupKey = cipherGroupKey(ks , ksPassword , secretKey);
					out.writeObject(groupID);
					int size=ciphGroupKey.length;
					out.writeInt(size);

					out.write(ciphGroupKey, 0, size);;

					return true;
				}

			} else if(command_type.equals("msg") || command_type.equals("m")) {

				if(full_command.size() >= 2) {

					out.writeObject("m");
					String groupID = full_command.get(0);
					String message = clientID+":";
					for(int i=1; i<full_command.size();i++) {
						message+=full_command.get(i)+" ";
					}

					out.writeObject(groupID);
					out.flush();
					int isValid=in.readInt();
					if(isValid==0) {
						int size = in.readInt();
						byte[]encriptedKey=new byte[size];
						in.read(encriptedKey, 0, size);
						Key groupKey=decypherGroupKey(ks,ksPassword,encriptedKey);
						Cipher c = Cipher.getInstance("AES");
						c.init(Cipher.ENCRYPT_MODE, groupKey);
						byte[] enc = c.doFinal(message.getBytes());
						int encSize=enc.length;
						out.writeInt(encSize);
						out.write(enc,0,encSize);
					}
					return true;

				}



			} else if(command_type.equals("addu") || command_type.equals("a")) {

				if(full_command.size() == 2) {

					out.writeObject("a");
					String userToAdd = full_command.get(0);
					String groupID = full_command.get(1);
					out.writeObject(userToAdd);
					out.writeObject(groupID);

					int isValid=in.readInt();
					if(isValid==0) {
						@SuppressWarnings("unchecked")
						Hashtable<String,PublicKey> publicKeys=(Hashtable<String, PublicKey>) in.readObject();
						KeyGenerator keyGen;
						keyGen = KeyGenerator.getInstance("AES");
						keyGen.init(128);
						Key secretKey = keyGen.generateKey();



						for(Map.Entry<String, PublicKey> entry: publicKeys.entrySet()) {
							byte[] ciphGroupKey = memberCipheredGroupKey(ks , ksPassword , secretKey, entry.getValue());
							out.writeObject(entry.getKey());
							int size=ciphGroupKey.length;
							out.writeInt(size);
							out.write(ciphGroupKey,0,size);
							out.flush();



						}

					}
					return true;


				}



			} else if(command_type.equals("removeu") || command_type.equals("r")) {

				if(full_command.size() == 2) {

					out.writeObject("r");
					String userToAdd = full_command.get(0);
					String groupID = full_command.get(1);

					out.writeObject(userToAdd);
					out.writeObject(groupID);

					int isValid=in.readInt();
					if(isValid==0) {
						@SuppressWarnings("unchecked")
						Hashtable<String,PublicKey> publicKeys=(Hashtable<String, PublicKey>) in.readObject();
						KeyGenerator keyGen;
						keyGen = KeyGenerator.getInstance("AES");
						keyGen.init(128);
						Key secretKey = keyGen.generateKey();



						for(Map.Entry<String, PublicKey> entry: publicKeys.entrySet()) {
							byte[] ciphGroupKey = memberCipheredGroupKey(ks , ksPassword , secretKey, entry.getValue());
							out.writeObject(entry.getKey());
							int size=ciphGroupKey.length;
							out.writeInt(size);
							out.write(ciphGroupKey,0,size);
							out.flush();



						}

					}

					return true;

				}

			} else if(command_type.equals("ginfo") || command_type.equals("g")) {

				if(full_command.size() == 0) {
					out.writeObject("ag");

					return true;
				}		

				if(full_command.size() == 1) {
					out.writeObject("g");
					out.writeObject(full_command.get(0));

					return true;
				}





			}else if(command_type.equals("collect") || command_type.equals("c")) {

				if(full_command.size() == 1) {

					out.writeObject("c");
					String groupID = full_command.get(0);
					out.writeObject(groupID);
					int length=in.readInt();
					if(length!=-1) {
						for(int i=0;i<length;i++) {
							int size=in.readInt();
							byte[]encriptedKey=new byte[size];
							in.read(encriptedKey,0,size);
							Key decriptedKey=decypherGroupKey(ks, ksPassword, encriptedKey);
							out.writeObject(decriptedKey);
							out.flush();
						}
					}
					return true;
				}
			}else if(command_type.equals("history") || command_type.equals("h")) {

				if(full_command.size() == 1) {

					out.writeObject("h");
					String groupID = full_command.get(0);
					out.writeObject(groupID);
					int length=in.readInt();
					if(length!=-1) {
						for(int i=0;i<length;i++) {
							int size=in.readInt();
							byte[]encriptedKey=new byte[size];
							in.read(encriptedKey,0,size);
							Key decriptedKey=decypherGroupKey(ks, ksPassword, encriptedKey);
							out.writeObject(decriptedKey);
							out.flush();
						}
					}

				
				return true;
				}
			}

		
		}catch (Exception e) {
			e.printStackTrace();
		}


		return false;


	}
	private static Key decypherGroupKey(String ks, String ksPassword, byte[] encriptedKey) {
		try {
			KeyStore ks1 = KeyStore.getInstance("JCEKS");
			FileInputStream keyIS = new FileInputStream(ks);
			ks1.load(keyIS, ksPassword.toCharArray());
			Enumeration<String> aliases = ks1.aliases();
			String alias = aliases.nextElement();
			Key privateKey = ks1.getKey(alias, ksPassword.toCharArray());
			Certificate certificate= ks1.getCertificate(alias);

			Cipher c = Cipher.getInstance("RSA");
			c.init(Cipher.UNWRAP_MODE, privateKey);
			Key secretKey = c.unwrap(encriptedKey, "AES", Cipher.SECRET_KEY);
			return secretKey;
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	private static byte[] memberCipheredGroupKey(String ks, String ksPassword, Key secretKey, PublicKey value) {
		try {
			KeyStore keystore	= KeyStore.getInstance("JCEKS");
			FileInputStream keyIS = new FileInputStream(ks);
			keystore.load(keyIS, ksPassword.toCharArray());
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.WRAP_MODE, value);
			byte[] cipheredKey=cipher.wrap(secretKey);
			return cipheredKey;
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] cipherGroupKey(String ks ,String ksPassword ,Key secretKey) {
		try {
			KeyStore keystore	= KeyStore.getInstance("JCEKS");
			FileInputStream keyIS = new FileInputStream(ks);
			keystore.load(keyIS, ksPassword.toCharArray());
			Enumeration<String> aliases = keystore.aliases();
			String alias = aliases.nextElement();
			Certificate c= keystore.getCertificate(alias);
			PublicKey pubKey= c.getPublicKey();
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.WRAP_MODE, pubKey);
			byte[] cipheredKey=cipher.wrap(secretKey);
			return cipheredKey;



		} catch(Exception e) {
			e.printStackTrace();
			return null;
		}


	}


}
