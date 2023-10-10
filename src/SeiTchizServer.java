import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.net.*;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import java.security.cert.X509Certificate;

public class SeiTchizServer {

	private final static String FOLLOWTABLENAME = "followedTable.dat";
	private final static String PHOTOLISTNAME = "photos.dat";
	private final static String PHOTODIR = "photos";
	private final static String GROUPDIR = "groups";
	private final static String CERTIFICATEDIR = "PubKeys";
	private final static File GROUPINFOFILE = new File("groupInfo.cif");
	private final static File USERFILE = new File("users.cif");
	private final static File USERFILEKEY = new File("userFileKey.cif");
	private final static String KEYSDIR = "Keys";


	private SeiTchizHandler stHandler;

	public SeiTchizServer(SeiTchizHandler stHandler) {
		this.stHandler = stHandler;
	}

	@SuppressWarnings("unchecked")
	public static void main(String[] args) {
		System.setProperty("javax.net.ssl.keyStore", args[1]);
		System.setProperty("javax.net.ssl.keyStorePassword", args[2]);
		String keyStore=args[1];
		String keyStorePass=args[2];


		try {

			if(!USERFILEKEY.exists()) {
				USERFILEKEY.createNewFile();
				KeyStore ks	= KeyStore.getInstance("JCEKS");
				FileInputStream keyIS = new FileInputStream(keyStore);
				KeyGenerator keyGen;

				keyGen = KeyGenerator.getInstance("AES");
				keyGen.init(128);
				Key secretKey = keyGen.generateKey();
				ks.load(keyIS, keyStorePass.toCharArray());

				byte []encoded = SeiTchizHandler.wrap(ks, keyStore, keyStorePass, secretKey);
				FileOutputStream fileKeyWriter = new FileOutputStream(USERFILEKEY);
				//ObjectOutputStream objKeyWriter= new ObjectOutputStream(fileKeyWriter);
				fileKeyWriter.write(encoded);
				//objKeyWriter.close();
				fileKeyWriter.close();


			}




			Hashtable<String,ArrayList<ArrayList<String>>> followTable;
			ArrayList<String> photoList;

			if (args.length == 3) {
				File f = new File(FOLLOWTABLENAME);
				File p = new File(PHOTOLISTNAME);
				File photoFolder=new File(PHOTODIR);
				File groupFolder=new File(GROUPDIR);
				File certificateFolder=new File(CERTIFICATEDIR);

				if(!USERFILE.exists()) {
					try {
						USERFILE.createNewFile();

					} catch (IOException e) {
						e.printStackTrace();
					}


				}

				if (!p.exists()) {
					photoList = new ArrayList<>();
					SeiTchizHandler.saveState(photoList,PHOTOLISTNAME,keyStore,keyStorePass);
				} else 
					photoList=(ArrayList<String>) SeiTchizHandler.loadState(PHOTOLISTNAME,keyStore,keyStorePass);

				if (!f.exists()) {
					followTable = new Hashtable<>();
					SeiTchizHandler.saveState(followTable,FOLLOWTABLENAME,keyStore,keyStorePass);
			        
				} else 
					followTable=(Hashtable<String, ArrayList<ArrayList<String>>>) SeiTchizHandler.loadState(FOLLOWTABLENAME,keyStore,keyStorePass);
				
				if(!photoFolder.exists())
					photoFolder.mkdir();

				if(!certificateFolder.exists())
					certificateFolder.mkdir();

				if(!groupFolder.exists())
					groupFolder.mkdir();

				if(!GROUPINFOFILE.exists())
					try {
						GROUPINFOFILE.createNewFile();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

				

				SeiTchizHandler stHandler = new SeiTchizHandler (followTable, photoList);

				int serverPort = Integer.parseInt(args[0]);
				System.out.println("SERVER:"+serverPort);
				SeiTchizServer server = new SeiTchizServer(stHandler);
				server.startServer(serverPort, keyStore,keyStorePass);

			} else {
				throw new IllegalArgumentException("Número incorreto de command line arguments. Deve colocar 3 argumentos: <serverport> <KeyStore> <KeyStorePassword>");
			}
		}catch(Exception e) {
			e.printStackTrace();
		}
	}


	@SuppressWarnings("unchecked")
	public void startServer (int port, String ks, String keyStorePass) {
		ServerSocketFactory ssf= SSLServerSocketFactory.getDefault();
		SSLServerSocket sSocket = null;

		try {
			sSocket=(SSLServerSocket) ssf.createServerSocket(port);
			while(true) {
				System.out.println("SERVER: Waiting for a connection..."); 
				Socket inSoc = sSocket.accept();
				ServerThread newServerThread = new ServerThread(inSoc,ks,keyStorePass);
				newServerThread.start();
			}
		} catch (IOException e ) {
			e.printStackTrace();
		}
	}


	class ServerThread extends Thread {

		private Socket socket = null;
		private String ks=null;
		private String keyStorePass=null;
		ServerThread(Socket inSoc, String keystore, String keyPass) {
			socket = inSoc;
			ks=keystore;
			keyStorePass=keyPass;

			System.out.println("SERVER THREAD: Criada nova thread para um cliente.");

		}

		public void run() {

			boolean userRunning = true;
			boolean authenticated = false;
			String clientID = "";

			try {
				ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
				ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());

				clientID=(String)inStream.readObject();
				byte[] nonce = new byte[8];

				new SecureRandom().nextBytes(nonce);
				String nonceString = new String(nonce);
				outStream.write(nonce,0,8);
				outStream.flush();

				boolean clientIdExists = stHandler.findUser(clientID,ks,keyStorePass);

				if(clientIdExists) {

					outStream.writeInt(1);
					outStream.flush();

					int length = inStream.readInt();  //recebe o tamanho da nonce encriptado
					byte[]encripted = new byte[length];
					inStream.readFully(encripted, 0, length);
					authenticated=stHandler.login(clientID, length,encripted,nonceString,ks, keyStorePass);
					if (authenticated) {
						outStream.writeObject("Success");
					} else {
						outStream.writeObject("Error");
					}




				} else {

					outStream.writeInt(0);
					outStream.flush();
					Cipher c= Cipher.getInstance("RSA");

					byte[] clientNonce = new byte[nonce.length];
					inStream.readFully(clientNonce,0,8);
					String clientNonceString=new String(clientNonce);

					int length = inStream.readInt();  //recebe o tamanho da nonce encriptado
					byte[]encripted = new byte[length];
					inStream.readFully(encripted, 0, length);
					String s = new String(encripted);
					Certificate certificate = (Certificate) inStream.readObject();

					PublicKey pk = certificate.getPublicKey();
					c.init(Cipher.DECRYPT_MODE, pk);
					String decryptedData = new String(c.doFinal(encripted));

					if(clientNonceString.contentEquals(nonceString)) {
						if(nonceString.contentEquals(decryptedData)) {
							int isValid = stHandler.createAccount(clientID,ks,keyStorePass,certificate);
							if (isValid==1) {
								outStream.writeObject("Success");
							} else if(isValid==-1) {
								outStream.writeObject("Error");
								return;
							}
							else {
								outStream.writeObject("NoSuchClientID");
							}
						}

					}



				}
				/*
				if (clientIdExists) {
					authenticated = stHandler.login (credentials[0], credentials[1]);
					if (!authenticated) {
						outStream.writeObject("Error");
						return;
						// Do lado do cliente, este deve dar uma excecao de InvalidCredentialException e terminar.
					}else {
						outStream.writeObject("Success");
					}
				} else {
					// Se não existe um utilizador com o clientID passado, avisa o cliente para indicar um username para criar a conta.
					outStream.writeObject("NoSuchClientID");
					String username = (String) inStream.readObject();
					authenticated = stHandler.createAccount(credentials[0], username, credentials[1]);
					if (authenticated) {
						outStream.writeObject("Success");
					} else {
						outStream.writeObject("Error");
					}
				}
				 */
				System.out.println("SERVER THREAD: "+ clientID + " sucessfully authenticated and is now logged in.");
				String command_type = "";

				while(userRunning) {
					command_type = (String) inStream.readObject();
					String reply = stHandler.handleCommand(command_type, clientID, inStream,outStream, ks, keyStorePass);
					outStream.writeObject(reply);
					outStream.flush();
				}

			} catch (IOException e2) {
				System.out.println("SERVER THREAD: " + clientID + " has logged off.");
				return;
			}
			catch (Exception e ) {
				System.exit(-1);
			}
		}
	}
}

