
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.util.Arrays;
import java.io.Writer;
public class SeiTchizHandler {
	private final static File USERFILE = new File("users.cif");
	private final static File GROUPINFOFILE = new File("groupInfo.cif");
	private final static String FOLLOWTABLENAME = "followedTable.dat";
	private final static String PHOTOLISTNAME = "photos.dat";
	private final static String CERTIFICATEDIR = "PubKeys";
	private final static String PHOTODIR = "photos";
	private final static String GROUPDIR = "groups";
	private final static File USERFILEKEY = new File("userFileKey.cif");
	private final static File USEDKEYSTORES = new File("usedKeyStores.cif");
	private final static String KEYSDIR = "keys";
	private Hashtable<String,ArrayList<ArrayList<String>>> followTable;
	private ArrayList<String> photoList;

	public SeiTchizHandler (Hashtable<String,ArrayList<ArrayList<String>>> ft, ArrayList<String> pl) {
		this.followTable = ft;
		this.photoList = pl;
	}

	public boolean login (String clientID,int length, byte[] encripted, String nonceString, String ks, String ksPass) {
		try {


			File certFile = new File(CERTIFICATEDIR +File.separator + clientID+".cer");
			if(certFile.exists()) {
				Key secretKey=getSecretKey(ks, ksPass);
				byte [] desincripted = new byte[256];
				KeyStore store = KeyStore.getInstance("JCEKS");
				FileInputStream inputStream = new FileInputStream(ks);
				store.load(inputStream, ksPass.toCharArray());

				desincripted= decryptFile( ks, ksPass , secretKey, USERFILE);
				String ficheiro=new String(desincripted);
				String []decript = ficheiro.split("\n");
				String decriptFinalUser=new String();
				String decriptFinalfile=new String();
				for(int i =0;i<decript.length;i++) {
					if(decript[i].split(":")[0].equals(clientID)) {
						decriptFinalUser=decript[i].split(":")[0];
						decriptFinalfile=decript[i].split(":")[1];
						break;
					}
				}
				if(decriptFinalUser.equals(clientID)) {
					CertificateFactory fact = CertificateFactory.getInstance("X.509");
					decriptFinalfile=decriptFinalfile.split(".cer")[0];
					FileInputStream is = new FileInputStream (decriptFinalfile+".cer");
					Certificate cer = fact.generateCertificate(is);
					PublicKey key = cer.getPublicKey();


					Cipher c = Cipher.getInstance("RSA");
					c.init(Cipher.DECRYPT_MODE, key);


					byte[] decrypted = c.doFinal(encripted);
					String decryptedData=new String(decrypted);
					if(nonceString.contentEquals(decryptedData)) {
						return true;
					}
				}
				return false;
			}


		} catch (Exception e) {
			e.printStackTrace();
			return false; 
		}
		return false;

	}

	public int createAccount(String clientID, String ks, String ksPassword, Certificate clientCertificate) {

		try {
			if(!USEDKEYSTORES.exists()) {
				USEDKEYSTORES.createNewFile();
			}





			Key secretKey=getSecretKey(ks, ksPassword);
			byte [] desincripted = new byte[256];
			KeyStore store = KeyStore.getInstance("JCEKS");
			FileInputStream inputStream = new FileInputStream(ks);
			store.load(inputStream, ksPassword.toCharArray());



			PublicKey clientPK= clientCertificate.getPublicKey();
			String pkString=new String(clientPK.getEncoded());
			byte[]keyscombined;
			byte[] decriptedUsed=new byte[256];
			byte[]toaddKS=clientCertificate.getPublicKey().getEncoded();
			byte[]space= "--separated--".getBytes();
			byte[]allToAdd= new byte[toaddKS.length+space.length];
			int length=0;

			for (byte curByte : toaddKS)
			{
				allToAdd[length] = curByte;
				length++;
			}


			for (byte curByte  : space)
			{
				allToAdd[length] = curByte;
				length++;
			}

			if(USEDKEYSTORES.length()!=0) {
				decriptedUsed= decryptFile( ks, ksPassword , secretKey, USEDKEYSTORES);
				keyscombined=new byte[decriptedUsed.length+allToAdd.length];
				String[]usedKeys= new String(decriptedUsed).split("--separated--");
				for(String x: usedKeys) {
					if(x.contentEquals(pkString)) {
						return -1;
					}
				}

			}

			else {
				keyscombined=new byte[allToAdd.length];
			}
			int j=0;
			if(USEDKEYSTORES.length()!=0) {
				for (byte curByte : decriptedUsed)
				{
					keyscombined[j] = curByte;
					j++;
				}
			}

			for (byte curByte  : allToAdd)
			{
				keyscombined[j] = curByte;
				j++;
			}

			encryptFile(ks,ksPassword,toaddKS, secretKey,USEDKEYSTORES);



			byte[] toAddBytes = (clientID+":" + CERTIFICATEDIR +File.separator + clientID+".cer"+ "\n").getBytes();			
			byte[] combined;
			int i = 0;

			if(USERFILE.length()!=0) {
				desincripted= decryptFile( ks, ksPassword , secretKey, USERFILE);
				combined=new byte[desincripted.length+toAddBytes.length];
			}
			else
				combined=new byte[toAddBytes.length];


			if(USERFILE.length()!=0) {
				for (byte curByte : desincripted)
				{
					combined[i] = curByte;
					i++;
				}
			}

			for (byte curByte  : toAddBytes)
			{
				combined[i] = curByte;
				i++;
			}
			/*new byte[desincripted.length+toAddBytes.length];
			System.arraycopy(desincripted , 0 , combined , 0 , desincripted.length);
			System.arraycopy(toAddBytes , 0 , combined , desincripted.length , toAddBytes.length);
			 */
			boolean wasEncripted=encryptFile(ks,ksPassword,combined, secretKey,USERFILE);

			if (wasEncripted) {

				byte[] encodedCert = clientCertificate.getEncoded();
				File certificateFile = new File(CERTIFICATEDIR +File.separator + clientID+".cer");

				FileOutputStream fos;
				fos = new FileOutputStream(certificateFile);


				fos.write(encodedCert);
				fos.close();


				ArrayList<ArrayList<String>>listaMae = new ArrayList<>();
				listaMae.add(new ArrayList<>());
				listaMae.add(new ArrayList<>());

				followTable.put(clientID,listaMae);
				saveState(followTable,FOLLOWTABLENAME,ks,ksPassword);

				return 1;
			}
			return 0;

		} catch (Exception e) {
			e.printStackTrace();
			return 0;
		}
	}

	public boolean findUser (String clientID , String ks, String ksPassword) {



		try {
			Key secretKey=getSecretKey(ks, ksPassword);
			byte [] desincripted = new byte[256];
			KeyStore store = KeyStore.getInstance("JCEKS");
			FileInputStream inputStream = new FileInputStream(ks);
			store.load(inputStream, ksPassword.toCharArray());






			if(USERFILE.length()!=0) {
				desincripted= decryptFile(ks, ksPassword , secretKey, USERFILE);
				String ficheiro=new String(desincripted);
				String []array=ficheiro.split("\n");
				for(String line : array) {
					System.out.println(line.split(":")[0]);
					if(line.split(":")[0].equals(clientID))
						return true;
				}
			}
			return false;


		} catch (Exception e) {
			e.printStackTrace();
			return false; //And System.exit(-1) ?
		}

	}



	public String handleCommand(String command_type, String clientID, ObjectInputStream in, ObjectOutputStream out, String ks, String keyStorePass) throws FileNotFoundException {

		String replyMessage = "";

		try {

			if (command_type.equals("v")) {	
				List<String> followers = getFollowers(clientID);
				if(followers.isEmpty()) 
					replyMessage = ("You don't have any followers");
				else
					replyMessage = "Your followers:\n" + stringify(followers, "\n");

			} else if (command_type.equals("f")) {
				String followedID;
				followedID = (String) in.readObject();
				int successful_follow = follow (clientID, followedID);

				if (successful_follow==0) {
					saveState(followTable,FOLLOWTABLENAME,ks,keyStorePass);

					replyMessage = "Sucessful follow.";
				} 
				else if(successful_follow==-1)
					replyMessage = "Error: You can't follow yourself!";

				else if(successful_follow==-2) 
					replyMessage = "Error: That user does not exist!";

				else if(successful_follow==-3) 
					replyMessage = "Error: You're already following this user!";


			} else if (command_type.equals("u")) {
				String followedID;
				followedID = (String) in.readObject();
				int successful_unfollow = unfollow (clientID, followedID);

				if (successful_unfollow==0) {
					saveState(followTable,FOLLOWTABLENAME,ks,keyStorePass);
					replyMessage = "Sucessful unfollow.";

				} 
				else if(successful_unfollow==-1)
					replyMessage = "Error: You can't unfollow yourself!";

				else if(successful_unfollow==-2) 
					replyMessage = "Error: That user does not exist!";

				else if(successful_unfollow==-3) 
					replyMessage = "Error: You're not following this user!";


			} else if(command_type.equals("p")) {

				int fileSize = in.readInt();
				byte [] fileBuffer = new byte [fileSize];

				in.readFully(fileBuffer, 0, fileSize);
				boolean successful_post = post(clientID,fileBuffer,ks,keyStorePass);
				if(successful_post) {
					replyMessage = "Photo posted successfuly.";
					saveState(photoList, PHOTOLISTNAME,ks,keyStorePass);
				} else
					replyMessage = "Error: Could not post the requested Photo.";


			} else if (command_type.equals("l")) {

				String photoID = (String) in.readObject();
				int successfulLike = like(clientID, photoID);

				if (successfulLike==0) {
					saveState(photoList, PHOTOLISTNAME,ks,keyStorePass);
					replyMessage = "Photo has been liked!";
				}
				else if(successfulLike==-1)
					replyMessage="Error: You have already liked this photo";
				else
					replyMessage = "Error: There is no photo with that ID.";


			} else if(command_type.equals("w")) {

				int number_Of_Photos = in.readInt();
				boolean hasPhotos = getWall(number_Of_Photos,clientID,out,ks,keyStorePass);

				if (hasPhotos)
					replyMessage = "Photos sent successfuly";
				else
					replyMessage = "Error: There are no photos to send.";

			} else if (command_type.equals("n")) {
				String groupID = (String) in.readObject();
				int size= in.readInt();
				byte[] ciphGroupKey = new byte[size];
				in.read(ciphGroupKey, 0, size);
				int identifier=0;

				boolean groupCreated = createGroup(clientID, groupID,ciphGroupKey,identifier,ks , keyStorePass);

				if (groupCreated)
					replyMessage = "Group " + groupID + " created sucessfully";
				else
					replyMessage = "Error: That group already exists.";


			} else if (command_type.equals("m")) {

				String groupID = (String) in.readObject();
				int messageWritten = writeMSG (clientID, groupID,ks,keyStorePass,out,in);

				if (messageWritten==0)
					replyMessage = "Message sent successfully";
				else
					if(messageWritten==-1)
						replyMessage = "Error: This group does not exist.";
					else
						replyMessage = "Error: You do not belong to this group.";




			} else if (command_type.equals("a")) {

				String user = (String) in.readObject();
				String group= (String) in.readObject();

				int wasUserAdded = addUser(clientID, user, group ,ks, keyStorePass, out,in) ;

				if (wasUserAdded==0)
					replyMessage = "User added successfully";
				else if(wasUserAdded==-1)
					replyMessage = "Error: That group does not exist.";
				else if(wasUserAdded==-2)
					replyMessage = "Error: You're not the owner of this group.";
				else if(wasUserAdded==-3)
					replyMessage = "Error: That user already belongs to the group.";
				else if(wasUserAdded==-4)
					replyMessage = "Error: You cannot add yourself.";
				else if(wasUserAdded==-5) {
					replyMessage = "Error: That user does not exist!";

				}


			} else if (command_type.equals("r")) {

				String user = (String) in.readObject();
				String group= (String) in.readObject();
				int wasUserRemoved = removeUser(clientID, user ,group,ks, keyStorePass,out,in) ;

				if (wasUserRemoved==0)
					replyMessage = "User removed successfully";
				else if(wasUserRemoved==-1)
					replyMessage = "Error: That group does not exist";
				else if(wasUserRemoved==-2)
					replyMessage = "Error: You're not the owner of this group.";
				else if(wasUserRemoved==-3)
					replyMessage = "Error: That user does not belong to the group.";
				else if(wasUserRemoved==-4)
					replyMessage = "Error: You cannot remove yourself.";


			} else if (command_type.equals("ag")) {


				replyMessage = getUserGroupInfo(clientID,ks, keyStorePass);

			} else if (command_type.equals("g")) {

				String groupID = (String) in.readObject();

				replyMessage = getGroupInfo(clientID, groupID,ks, keyStorePass);


			} else if (command_type.equals("c")) {

				String groupID = (String) in.readObject();

				replyMessage = collectMessages(clientID, groupID,ks, keyStorePass,out,in);

			} else if (command_type.equals("h")) {

				String groupID = (String) in.readObject();
				if(groupExists(groupID)) {
					if(getGroupMembers(groupID,ks,keyStorePass).contains(clientID))
						replyMessage = history(clientID, groupID,ks,keyStorePass, out, in);
					else
						replyMessage = "Error: You do not belong to this group";
				}else {
					replyMessage = "Error: That group does not exist.";
				}
			}

			else {
				replyMessage = "Could not process the request.";
			}

		} catch (ClassNotFoundException | IOException e ) {
			e.printStackTrace();
		}

		return replyMessage;

	}


	private static File getChatLogFile(String groupID) {
		File chatLog=new File(GROUPDIR+File.separator+groupID+File.separator+"chatLog");
		if(!chatLog.exists())
			chatLog.mkdir();

		return new File(GROUPDIR+File.separator+groupID+File.separator+"chatLog"+File.separator+"groupInbox_"+ groupID+ ".txt");
	}

	private static File getInboxFile(String groupID) {
		File inboxDir=new File(GROUPDIR+File.separator+groupID+File.separator+"inbox");
		if(!inboxDir.exists())
			inboxDir.mkdir();

		return inboxDir;
	}


	private static File getSecificGroupInfo(String groupID,String clientID, int identifier) {
		return new File(GROUPDIR+File.separator+groupID+File.separator+clientID+"-"+identifier+".cif");
	}

	private File createIdentifierInfo(String groupID) {
		return new File(GROUPDIR+File.separator+groupID+File.separator+"currentGroupKey.txt");
	}

	private String history (String clientID, String groupID,String ks, String ksPass, ObjectOutputStream out, ObjectInputStream in) {
		try {
			StringBuilder sb=new StringBuilder();
			List<String> readableMessages=new ArrayList<String>();
			File whoCanSeehistory=new File(GROUPDIR+File.separator+groupID+File.separator+"chatLog"+File.separator+"messagePermitedUsers.cif");
			if(!whoCanSeehistory.exists()) {
				out.writeInt(-1);
				return "You have no message history from the group: " + groupID ;
			}
				
			byte[]decriptedUsers=new byte[256];
			Key secretKey=getSecretKey(ks, ksPass);
			decriptedUsers=decryptFile(ks, ksPass, secretKey, whoCanSeehistory);
			String [] usersWhoCanSeeMessages= new String(decriptedUsers).split("\n");
			for(String linha:usersWhoCanSeeMessages) {
				if(linha.split(":").length>2) {
					String messagePos=linha.split(":")[0];
					List<String> usersPermitted=new ArrayList<>(Arrays.asList(linha.split(":")[2].split(",")));	
					String identifier=linha.split(":")[1];
					if(usersPermitted.contains(clientID)){
						readableMessages.add(messagePos+":"+identifier);

				}
				
				}
			}
			if(readableMessages.size()==0)
				out.writeInt(-1);
			else
				out.writeInt(readableMessages.size());
			for(String messageElement:readableMessages) {
				File getSecretKey= new File(GROUPDIR+File.separator+groupID+File.separator+clientID+"-"+messageElement.split(":")[1]+".cif");
				FileInputStream userKey=new FileInputStream(getSecretKey);
				//ObjectInputStream streamKey=new ObjectInputStream(userKey);
				int size=(int) getSecretKey.length();
				byte[]encriptedKey=new byte[size];
				userKey.read(encriptedKey);
				//streamKey.close();
				userKey.close();
				out.writeInt(encriptedKey.length);
				out.flush();
				out.write(encriptedKey,0,encriptedKey.length);
				out.flush();
				Key decriptedKey=(Key) in.readObject();

				File message=new File(GROUPDIR+File.separator+groupID+File.separator+"chatLog"+File.separator+"Message"+messageElement.split(":")[0]+"-"+messageElement.split(":")[1]+".cif");
				byte[]messageBytes=new byte[256];
				messageBytes=decryptFile(ks, ksPass, decriptedKey, message);
				String messageContent=new String(messageBytes).split(":")[1];
				String senderID=new String(messageBytes).split(":")[0];
				sb.append(senderID + ": " + messageContent + "\n");
			
			
			
			
		

			}
			if(sb.length()==0)
				return "You have no new messages";
			else
				return sb.toString();

		} catch (Exception e) {
			e.printStackTrace();
		}

		return "You have no message history" + groupID ;
	}

	private String collectMessages(String clientID, String groupID, String ks, String ksPass, ObjectOutputStream out, ObjectInputStream in) {
		StringBuilder sb= new StringBuilder();
		List<String> readableMessages=new ArrayList<String>();
		File whoCanSeehistory=new File(GROUPDIR+File.separator+groupID+File.separator+"chatLog"+File.separator+"messagePermitedUsers.cif");

		try {
			File inbox= getInboxFile(groupID);
			if(inbox.exists()) {

				if(getGroupMembers(groupID,ks,ksPass).contains(clientID)) {
					String toEncriptUsers="";
					String toEncriptHistory="";
					File whoCanSeeThisMessage=new File(GROUPDIR+File.separator+groupID+File.separator+"inbox"+File.separator+"messagePermitedUsers.cif");
					byte[]decriptedUsers=new byte[256];
					Key secretKey=getSecretKey(ks, ksPass);
					decriptedUsers=decryptFile(ks, ksPass, secretKey, whoCanSeeThisMessage);
					String [] usersWhoCanSeeMessages= new String(decriptedUsers).split("\n");

					for(String linha:usersWhoCanSeeMessages) {
						if(linha.split(":").length>2) {
							String messagePos=linha.split(":")[0];
							List<String> usersPermitted=new ArrayList<>(Arrays.asList(linha.split(":")[2].split(",")));	
							String identifier=linha.split(":")[1];
							toEncriptUsers+=messagePos+":"+identifier+":";

							for(int i = 0; i < usersPermitted.size(); i++) {
								if(i<usersPermitted.size()-1)
									toEncriptUsers+=usersPermitted.get(i)+",";
								else
									toEncriptUsers+=usersPermitted.get(i)+":";
							}

							if(linha.split(":").length==4) {

								List<String> usersWhoSaw = new ArrayList<>(Arrays.asList(linha.split(":")[3].split(",")));
								for(int i =0;i< usersWhoSaw.size();i++) {
									if(i<usersWhoSaw.size()-1) {
										toEncriptUsers+=usersWhoSaw.get(i)+",";
									}
									else
										toEncriptUsers+=usersWhoSaw.get(i);

								}
								if(!usersWhoSaw.contains(clientID) && usersPermitted.contains(clientID)) {
									readableMessages.add(messagePos+":"+identifier);
									toEncriptUsers+=","+clientID+"\n";
									usersWhoSaw.add(clientID);
								}
								else {
									toEncriptUsers+="\n";
	
								}
								
									Collections.sort(usersWhoSaw);
									Collections.sort(usersPermitted);


									if(usersWhoSaw.equals(usersPermitted)) {
										File historyFile=new File(GROUPDIR+File.separator+groupID+File.separator+"chatLog"+File.separator+"Message"+messagePos+"-"+identifier+".cif");
										if(!historyFile.exists())
											historyFile.createNewFile();
										
										
										toEncriptHistory+=messagePos+":"+identifier+":";
										for(int i =0;i< usersPermitted.size();i++) {
											if(i<usersPermitted.size()-1) {
												toEncriptHistory+=usersPermitted.get(i)+",";
											}
											else
												toEncriptHistory+=usersPermitted.get(i)+"\n";
										}



									}

								
							}
							
							else {
								if(usersPermitted.contains(clientID)) {
									readableMessages.add(messagePos+":"+identifier);
									toEncriptUsers+=clientID+"\n";
								}
								else {
									toEncriptUsers+="\n";
								}
									if(usersPermitted.size()==1) {
										File historyFile=new File(GROUPDIR+File.separator+groupID+File.separator+"chatLog"+File.separator+"Message"+messagePos+"-"+identifier+".cif");
										if(!historyFile.exists())
											historyFile.createNewFile();

										toEncriptHistory+=messagePos+":"+identifier+":";
										for(int i =0;i< usersPermitted.size();i++) {
											if(i<usersPermitted.size()-1) {
												toEncriptHistory+=usersPermitted.get(i)+",";
											}
											else
												toEncriptHistory+=usersPermitted.get(i)+"\n";
										}
								}
							
						}
					}
				}
					encryptFile(ks, ksPass, toEncriptUsers.getBytes(), secretKey,whoCanSeeThisMessage);
					if(readableMessages.size()==0)
						out.writeInt(-1);
					else
						out.writeInt(readableMessages.size());
					for(String messageElement:readableMessages) {
						File getSecretKey= new File(GROUPDIR+File.separator+groupID+File.separator+clientID+"-"+messageElement.split(":")[1]+".cif");
						FileInputStream userKey=new FileInputStream(getSecretKey);
						//ObjectInputStream streamKey=new ObjectInputStream(userKey);
						int size=(int) getSecretKey.length();
						byte[]encriptedKey=new byte[size];
						userKey.read(encriptedKey);
						//streamKey.close();
						userKey.close();
						out.writeInt(encriptedKey.length);
						out.flush();
						out.write(encriptedKey,0,encriptedKey.length);
						out.flush();
						Key decriptedKey=(Key) in.readObject();

						File message=new File(GROUPDIR+File.separator+groupID+File.separator+"inbox"+File.separator+"Message"+messageElement.split(":")[0]+"-"+messageElement.split(":")[1]+".cif");
						byte[]messageBytes=new byte[256];
						messageBytes=decryptFile(ks, ksPass, decriptedKey, message);
						String messageContent=new String(messageBytes).split(":")[1];
						String senderID=new String(messageBytes).split(":")[0];
						sb.append(senderID + ": " + messageContent + "\n");
						File historyFile=new File(GROUPDIR+File.separator+groupID+File.separator+"chatLog"+File.separator+"Message"+messageElement.split(":")[0]+"-"+messageElement.split(":")[1]+".cif");
						
						if(historyFile.exists()) {
							encryptFile(ks, ksPass, messageBytes, decriptedKey, historyFile);
						}
							
						if(!toEncriptHistory.equals(""))
							encryptFile(ks, ksPass, toEncriptHistory.getBytes(), secretKey, whoCanSeehistory);


					}

				}else {
					out.writeInt(-1);
					return "Error: You do not belong to this group";
				}


			}else {
				out.writeInt(-1);
				return "Error: That group does not exist.";
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		if(sb.length()==0)
			return "You have no new messages";

		return "New Messages:\n"+sb.toString();
	}



	private String getGroupInfo (String clientID, String groupID, String ks, String ksPass) {

		StringBuilder sbMembers = new StringBuilder();
		String groupOwner = "";

		try {

			if (!groupExists(groupID))
				return "Error: That group does not exist.";
			byte[] decripted= new byte[256];

			Key secretKey=getSecretKey(ks, ksPass);

			decripted=decryptFile(ks, ksPass, secretKey, GROUPINFOFILE);

			String []lines=new String(decripted).split("\n");


			for(String line :lines) {

				String[] lineSplitted = line.split(":");
				String group = lineSplitted[0]; 
				String gOwner = lineSplitted[1];
				String[] members = lineSplitted[2].split(",");

				if(group.equals(groupID)) {
					groupOwner = gOwner;
					boolean belongsToGroup = false;

					sbMembers.append("Group members:\n");

					for(String m : members) {
						if (m.equals(clientID))
							belongsToGroup = true;
						sbMembers.append("- " + m + "\n");
					}

					if (!belongsToGroup) {
						return "Error: You don't belong to this group";
					}

					break;
				}
			}



		} catch (Exception e) {
			e.printStackTrace();
		}


		return "Group Owner:\n- " + groupOwner + "\n" + sbMembers.toString();

	}

	private String getUserGroupInfo(String clientID, String ks, String ksPass) {
		ArrayList<String> ownerList = new ArrayList<>();
		ArrayList<String> memberList = new ArrayList<>();
		StringBuilder sb = new StringBuilder();

		try {
			byte[] decripted= new byte[256];

			Key secretKey=getSecretKey(ks, ksPass);

			decripted=decryptFile(ks, ksPass, secretKey, GROUPINFOFILE);

			String []lines=new String(decripted).split("\n");


			for(String line :lines) {

				String[] lineSplitted = line.split(":");
				String groupID = lineSplitted[0]; //nome do grupo
				String owner = lineSplitted[1];		//nome do owner

				if(owner.equals(clientID)) {
					ownerList.add(groupID);
					memberList.add(groupID);

				} else {

					String[] members = lineSplitted[2].split(",");
					ArrayList<String> groupMembers = new ArrayList<>(Arrays.asList(members));

					if(groupMembers.contains(clientID)) {
						memberList.add(groupID);
					}
				}

			}


			if (!ownerList.isEmpty()) {
				sb.append("Owned Groups:\n");

				for(String o : ownerList) 
					sb.append("- " + o + "\n");

			} else {
				sb.append("You're not the owner of any group!\n");
			}

			sb.append("===============================\n");

			if (!memberList.isEmpty()) {
				sb.append("Groups you belong to:\n");

				for(String m : memberList) 
					sb.append("- " + m + "\n");

			} else {
				sb.append("You don't belong to any group!\n");
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		return sb.toString();

	}



	private boolean post (String clientID, byte[] fileBuffer,String ks,String ksPassword) {

		try {

			String uniqueID = UUID.randomUUID().toString();
			String filePath = clientID + "_" + uniqueID.substring(0, uniqueID.length()/2) +".jpg";
			File fileReceived = new File(PHOTODIR +File.separator + filePath);
			File hashFile=new File(PHOTODIR +File.separator+clientID + "_" + uniqueID.substring(0, uniqueID.length()/2)+"_integrityVerifier");
			if(!hashFile.exists()) {
				hashFile.createNewFile();

			}
			Mac photoMac= Mac.getInstance("HmacSHA1");
			Key secretKey=getSecretKey(ks, ksPassword);



			FileOutputStream fos;
			fos = new FileOutputStream(fileReceived);

			OutputStream output = new BufferedOutputStream(fos);
			output.write(fileBuffer);
			output.close();
			fos.close();

			FileOutputStream outStream = new FileOutputStream(hashFile);
			ObjectOutputStream oos = new ObjectOutputStream(outStream);

			photoMac.init(secretKey);
			photoMac.update(fileBuffer);
			oos.writeObject(photoMac.doFinal());
			oos.close();
			outStream.close();
			photoList.add(clientID + "_" + uniqueID.substring(0, uniqueID.length()/2) + ":");			

			return true;

		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}

	private List<String> getFollowers(String clientID) throws FileNotFoundException {
		return  followTable.get(clientID).get(0);
	}

	private int follow (String clientID, String followedID) throws IOException  {

		if(clientID.equals(followedID)) 
			return -1;

		if(!followTable.containsKey(followedID)) 
			return -2;

		if(followTable.get(clientID).get(1).contains(followedID))
			return -3;

		followTable.get(clientID).get(1).add(followedID);
		followTable.get(followedID).get(0).add(clientID);

		return 0;
	}

	private int unfollow (String clientID, String unfollowedID) throws IOException  {

		if(clientID.equals(unfollowedID)) 
			return -1;

		if(!followTable.containsKey(unfollowedID))
			return -2;

		if(!followTable.get(clientID).get(1).contains(unfollowedID))
			return -3;

		followTable.get(clientID).get(1).remove(unfollowedID);
		followTable.get(unfollowedID).get(0).remove(clientID);

		return 0;
	}


	private int like (String clientID, String photoID) throws IOException {

		ArrayList<String> like;

		for(String linha :photoList) {

			String [] splitLinha = linha.split(":"); 

			if (splitLinha[0].equals(photoID)) {
				if (splitLinha.length == 2) {
					like = new ArrayList<> (Arrays.asList(splitLinha[1].split(",")));
					if (!like.contains(clientID)) {
						photoList.set(photoList.indexOf(linha), linha+","+clientID);
						return 0;
					} else {
						return -1;
					}
				}

				else {
					photoList.set(photoList.indexOf(linha), linha+clientID);
					return 0;
				}
			}
		}

		return -2;
	}


	private boolean getWall(int nPhotos ,String clientID, ObjectOutputStream outStream, String ks , String ksPassword) {

		try {
			int photoCounter = 0;
			ArrayList<String> files = new ArrayList<>();

			for (int i = photoList.size()-1 ; i>=0 ;i--) {

				if(photoCounter != nPhotos) {

					String userWhoPosted=photoList.get(i).split("_")[0];

					if(getFollowers(userWhoPosted).contains(clientID)) {
						files.add(photoList.get(i));	
						photoCounter++;
					}

				} else {
					break;
				}

			}
			if(photoCounter==0) {
				outStream.writeInt(-1);
				return false;
			}

			outStream.writeInt(photoCounter);


			for(String x: files) {
				String photo=x.split(":")[0];
				outStream.writeObject(photo);

				if((x.split(":").length)==2) {
					String likes=x.split(":")[1];
					outStream.writeObject(likes);

				} else {
					outStream.writeObject("null");
				}

				File photof = new File(PHOTODIR+File.separator+photo+".jpg");

				File verifyFile=new File(PHOTODIR +File.separator+photo+"integrityVerifierCreatedAtWall");
				if(!verifyFile.exists()) 
					verifyFile.createNewFile();

				Mac verifyMac= Mac.getInstance("HmacSHA1");
				Key secretKey=getSecretKey(ks, ksPassword);

				FileOutputStream outVerify = new FileOutputStream(verifyFile);
				ObjectOutputStream oos = new ObjectOutputStream(outVerify);


				FileInputStream photoFIS = new FileInputStream(photof);
				InputStream inStream = new BufferedInputStream(photoFIS);
				int fileSize = (int) photof.length();
				byte[] photoInBytes = new byte[fileSize];
				inStream.read(photoInBytes);



				verifyMac.init(secretKey);
				verifyMac.update(photoInBytes);
				oos.writeObject(verifyMac.doFinal());

				oos.close();
				outVerify.close();

				byte[]verify1=Files.readAllBytes(Paths.get(verifyFile.toURI()));
				byte[]verify2=Files.readAllBytes(Paths.get((PHOTODIR +File.separator+photo+"_integrityVerifier")));

				if(Arrays.equals(verify1, verify2)) {

					outStream.writeInt(1);
					outStream.writeInt(fileSize);
					outStream.flush();

					outStream.write(photoInBytes, 0, fileSize);
					outStream.flush();

					inStream.close();
					photoFIS.close();
				}
				else
					outStream.writeInt(0);
			}



		} catch (Exception e) {
			e.printStackTrace();
		}

		return true;
	}

	private boolean createGroup (String clientID, String groupID, byte[] key, int identifier,String ks, String ksPass) {




		if (!groupExists(groupID)) {
			try {
				File groupDir = new File(GROUPDIR+File.separator+groupID);
				if(!groupDir.exists())
					groupDir.mkdir();


				getInboxFile(groupID);
				getChatLogFile(groupID);

				File specificGroupInfo = getSecificGroupInfo(groupID,clientID,identifier);
				if(!specificGroupInfo.exists())
					specificGroupInfo.createNewFile();

				File currentIdentifier = createIdentifierInfo(groupID);
				if(!currentIdentifier.exists())
					currentIdentifier.createNewFile();

				BufferedWriter idenWriter=new BufferedWriter(new FileWriter(currentIdentifier));
				String a= new String(Integer.toString(identifier));
				idenWriter.write(a);
				idenWriter.close();








				byte[] toAddBytes = (groupID + ":"+ clientID + ":" + clientID+"\n").getBytes();			
				byte[] combined;
				int i = 0;
				byte [] desincripted = new byte[256];
				Key secretKey=getSecretKey(ks, ksPass);

				if(GROUPINFOFILE.length() != 0) {
					desincripted = decryptFile( ks, ksPass , secretKey, GROUPINFOFILE);
					combined = new byte[desincripted.length+toAddBytes.length];
				}
				else
					combined = new byte[toAddBytes.length];


				if(GROUPINFOFILE.length() != 0) {
					for (byte curByte : desincripted)
					{
						combined[i] = curByte;
						i++;
					}
				}

				for (byte curByte  : toAddBytes)
				{
					combined[i] = curByte;
					i++;
				}
				encryptFile(ks, ksPass, combined, secretKey, GROUPINFOFILE);

				FileOutputStream fileWriter = new FileOutputStream(specificGroupInfo, true);
				

				fileWriter.write(key);
				fileWriter.close();


			} catch (IOException e) {
				e.printStackTrace();
				return false;
			}

			return true;
		} 
		return false;
	}





	private int addUser (String clientID, String addedClientID, String groupID, String ks, String ksPass, ObjectOutputStream out, ObjectInputStream in) {

		try {


			Hashtable<String, Key> keysTableS=new Hashtable<>(); 
			if (!groupExists(groupID)) { 
				out.writeInt(-1);
				return -1;
			}


			ArrayList<String> members = getGroupMembers(groupID,ks,ksPass);
			if (!clientID.equals(getGroupOwner(groupID,ks,ksPass))) {
				out.writeInt(-1);
				return -2;
			}

			if(clientID.equals(addedClientID)) {
				out.writeInt(-1);
				return -4;
			}


			if(members.contains(addedClientID)) {
				out.writeInt(-1);
				return -3;
			}

			if(!userExists(ks,ksPass,addedClientID)) {
				out.writeInt(-1);
				return -5;
			}


			out.writeInt(0);
			BufferedReader idenReader=new BufferedReader(new FileReader(createIdentifierInfo(groupID)));
			int identifier = Integer.parseInt( idenReader.readLine());
			idenReader.close();
			identifier += 1;

			String content="";

			byte[] decripted= new byte[256];

			Key secretKey=getSecretKey(ks, ksPass);

			decripted=decryptFile(ks, ksPass, secretKey, GROUPINFOFILE);

			String []lines=new String(decripted).split("\n");


			for(String line :lines) {

				if(line.split(":")[0].equals(groupID))
					content+= line+","+addedClientID + "\n";
				else
					content+=line+"\n";
			}

			encryptFile(ks, ksPass, content.toString().getBytes(), secretKey, GROUPINFOFILE);
			members=getGroupMembers(groupID, ks, ksPass);
			for(String member:members) {
				File certFile = new File(CERTIFICATEDIR +File.separator +member+".cer");
				if(certFile.exists()) {
					CertificateFactory fact = CertificateFactory.getInstance("X.509");
					FileInputStream is = new FileInputStream (certFile);
					Certificate cer = fact.generateCertificate(is);
					PublicKey key =cer.getPublicKey();
					keysTableS.put(member,key);

				}


				BufferedWriter idenWriter=new BufferedWriter(new FileWriter(createIdentifierInfo(groupID)));
				String a= new String(Integer.toString(identifier));
				idenWriter.write(a);
				idenWriter.close();





			}
			out.writeObject(keysTableS);
			for(int i=0;i<keysTableS.size();i++) {
				String user=(String) in.readObject();
				int size=in.readInt();
				byte[]ciphKey=new byte[size];
				in.read(ciphKey, 0, size);
				File userGroupFileProv= new File(GROUPDIR+File.separator+groupID+File.separator+user+"-"+Integer.toString(identifier)+".cif");
				if(!userGroupFileProv.exists())
					userGroupFileProv.createNewFile();


				FileOutputStream fileWriter = new FileOutputStream(userGroupFileProv, true);
				//ObjectOutputStream objWriter = new ObjectOutputStream(fileWriter);
				fileWriter.write(ciphKey);
				//objWriter.close();
				fileWriter.close();



			}

			// Ir ao groupInfo.txt e adicionar addedClientID à linha correta
			// Ir ao groupInbox_<groupID>.txt e atualizar as cenas.


		} catch (Exception e) {
			e.printStackTrace();
		}


		return 0;

	}
	private boolean userExists(String ks, String ksPass, String addedClientID) {

		Key secretKey=getSecretKey(ks, ksPass);
		byte[] decripted= new byte[256];
		decripted=decryptFile(ks, ksPass, secretKey, USERFILE);
		String[] lines=new String(decripted).split("\n");
		for(String line:lines) {
			if(line.split(":")[0].equals(addedClientID))
				return true;
		}

		return false;
	}


	private boolean groupExists (String groupID) {
		File inboxDir=new File(GROUPDIR+File.separator+groupID+File.separator+"inbox");
		if(!inboxDir.exists())		
			return false;
		return true;
	}


	private int removeUser (String clientID, String remClientID, String groupID,String ks, String ksPass, ObjectOutputStream out, ObjectInputStream in) {

		try {
			Hashtable<String, Key> keysTableS=new Hashtable<>(); 

			if (!groupExists(groupID)) {
				out.writeInt(-1);
				return -1;
			}
			ArrayList<String> members = getGroupMembers(groupID,ks , ksPass);
			String content="";

			if (!clientID.equals(getGroupOwner(groupID,ks,ksPass))) {
				out.writeInt(-1);
				return -2;
			}

			if(!members.contains(remClientID)) {
				out.writeInt(-1);
				return -3;
			}

			if(clientID.equals(remClientID)) {
				out.writeInt(-1);
				return -4;
			}

			out.writeInt(0);

			BufferedReader idenReader=new BufferedReader(new FileReader(createIdentifierInfo(groupID)));
			int identifier = Integer.parseInt( idenReader.readLine());
			idenReader.close();
			identifier += 1;



			byte[] decripted= new byte[256];

			Key secretKey=getSecretKey(ks, ksPass);

			decripted=decryptFile(ks, ksPass, secretKey, GROUPINFOFILE);

			String []lines=new String(decripted).split("\n");




			for(String line : lines ) {

				if(line.split(":")[0].equals(groupID)) {

					String [] rest=line.split(":");
					content+=rest[0]+":"+rest[1]+":";
					String [] users=rest[2].split(",");

					for(int i =0;i<users.length;i++) {
						if(i==0 && i!=users.length-1 && !users[i].equals(remClientID)) {
							content+=users[i];
						}
						else if(!users[i].equals(remClientID) && i!=users.length-1) {
							content+=","+users[i];
						}
						else if(i==users.length-1 && !users[i].equals(remClientID))  {
							content+=content+=","+users[i]+"\n";

						}
						else if(!users[i].equals(remClientID)) {
							content+=users[i]+"\n";
						}
						else if(users[i].equals(remClientID) && i==users.length-1) {
							content+="\n";
						}
					}
				} else
					content+=line+"\n";
			}

			encryptFile(ks, ksPass, content.toString().getBytes(), secretKey, GROUPINFOFILE);
			members=getGroupMembers(groupID, ks, ksPass);
			for(String member:members) {
				File certFile = new File(CERTIFICATEDIR +File.separator +member+".cer");
				if(certFile.exists()) {
					CertificateFactory fact = CertificateFactory.getInstance("X.509");
					FileInputStream is = new FileInputStream (certFile);
					Certificate cer = fact.generateCertificate(is);
					PublicKey key =cer.getPublicKey();
					keysTableS.put(member,key);

				}


				BufferedWriter idenWriter=new BufferedWriter(new FileWriter(createIdentifierInfo(groupID)));
				String a= new String(Integer.toString(identifier));
				idenWriter.write(a);
				idenWriter.close();





			}
			out.writeObject(keysTableS);
			for(int i=0;i<keysTableS.size();i++) {
				String user=(String) in.readObject();
				int size=in.readInt();
				byte[]ciphKey=new byte[size];
				in.read(ciphKey, 0, size);

				File userGroupFileProv= new File(GROUPDIR+File.separator+groupID+File.separator+user+"-"+Integer.toString(identifier)+".cif");
				if(!userGroupFileProv.exists())
					userGroupFileProv.createNewFile();


				FileOutputStream fileWriter = new FileOutputStream(userGroupFileProv);
				//ObjectOutputStream objWriter = new ObjectOutputStream(fileWriter);
				fileWriter.write(ciphKey);
				//objWriter.close();
				fileWriter.close();




			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return 0;
		// Verificar se clientID é dono do grupo
		// Verificar se o addedClientID não pertence ao grup
	}


	private int writeMSG (String clientID, String groupID, String ks, String ksPass, ObjectOutputStream out, ObjectInputStream in) {

		// Verificar se clientID pertence ao grupo


		if (!groupExists(groupID)) {

			try {
				out.writeInt(-1);
				out.flush();
			} catch (IOException e) {
				e.printStackTrace();
			}
			return -1;

		} else {
			ArrayList<String> members = getGroupMembers(groupID, ks, ksPass);

			if (members.contains(clientID)) {
				try {
					out.writeInt(0);
					out.flush();
					int pos=0;
					Key secretKey=getSecretKey(ks, ksPass);
					String previouslySaved="";
					File messagePos=new File(GROUPDIR+File.separator+groupID+File.separator+"inbox"+File.separator+"currentPos");
					if(!messagePos.exists()) {
						messagePos.createNewFile();
					}


					else {
						BufferedReader posReader=new BufferedReader(new FileReader(messagePos));
						pos= Integer.parseInt( posReader.readLine());
						posReader.close();
					}

					FileInputStream userInputStream;
					BufferedReader idenReader=new BufferedReader(new FileReader(createIdentifierInfo(groupID)));
					int identifier = Integer.parseInt( idenReader.readLine());
					idenReader.close();

					File whocanSeeThisMessage=new File(GROUPDIR+File.separator+groupID+File.separator+"inbox"+File.separator+"messagePermitedUsers.cif");
					if(!whocanSeeThisMessage.exists()) {
						whocanSeeThisMessage.createNewFile();
					}
					else {
						byte[] decripted= decryptFile(ks, ksPass, secretKey, whocanSeeThisMessage);
						previouslySaved=new String(decripted);
					}
					
					String usersAllowed=previouslySaved+""+pos+":"+identifier+":";

					for (int i=0;i<members.size();i++)
					{
						if (i!=members.size()-1)
							usersAllowed += members.get(i) + ",";

						else
							usersAllowed += members.get(i)+":";
					}
					usersAllowed+="\n";

					byte[]allowed=usersAllowed.getBytes();
					encryptFile(ks, ksPass, allowed, secretKey, whocanSeeThisMessage);




					File message=new File(GROUPDIR+File.separator+groupID+File.separator+"inbox"+File.separator+"Message"+ Integer.toString(pos)+"-"+identifier+".cif");
					message.createNewFile();
					pos+=1;



					BufferedWriter posWriter=new BufferedWriter(new FileWriter(messagePos));
					posWriter.write(""+pos);
					posWriter.close();




					int fileSize=0;
					if(clientID.equals(getGroupOwner(groupID,ks,ksPass))) {
						userInputStream = new FileInputStream(getSecificGroupInfo(groupID,clientID,identifier));
						fileSize=(int) getSecificGroupInfo(groupID,clientID,identifier).length();
					}
					else {
						userInputStream = new FileInputStream(new File(GROUPDIR+File.separator+groupID+File.separator+clientID+"-"+identifier+".cif"));
						fileSize=(int) new File(GROUPDIR+File.separator+groupID+File.separator+clientID+"-"+identifier).length();
					}






					//ObjectInputStream utilizadorInputStream = new ObjectInputStream(userInputStream);
					byte [] file=new byte[fileSize];
					userInputStream.read(file);
					//utilizadorInputStream.close();
					userInputStream.close();

					int tamanho = file.length;
					out.writeInt(tamanho);
					out.flush();
					out.write(file, 0, tamanho);
					out.flush();

					int size=in.readInt();
					byte[]encriptedMessage=new byte[size];
					in.read(encriptedMessage, 0, size);

					FileOutputStream fileKeyWriter = new FileOutputStream(message);
					//ObjectOutputStream objKeyWriter= new ObjectOutputStream(fileKeyWriter);
					fileKeyWriter.write(encriptedMessage);
					//objKeyWriter.close();
					fileKeyWriter.close();

				}catch (IOException e){
					e.printStackTrace();
				}

				return 0;
			}
			try {
				out.writeInt(-1);
				out.flush();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return -2;
	}

	private ArrayList<String> getGroupMembers (String groupID, String ks, String ksPass) {

		ArrayList<String> members = new ArrayList<>();

		try {
			byte[] decripted= new byte[256];
			Key secretKey=getSecretKey(ks, ksPass);
			decripted=decryptFile(ks, ksPass, secretKey, GROUPINFOFILE);
			String []lines=new String(decripted).split("\n");
			/*
			BufferedReader groupInfoReader = new BufferedReader (new FileReader (GROUPINFOFILE));
			String line = "";
			 */
			String [] splitLine = new String [3];


			for(String line:lines) {
				splitLine = line.split(":");
				if (splitLine[0].equals(groupID)) {
					if (!splitLine[2].equals("none")) {
						String [] membersArray = splitLine[2].split(",");
						members = new ArrayList<>(Arrays.asList(membersArray));

					} else {
						break;
					}
				}
			}
			//groupInfoReader.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

		return members;

	}

	private String getGroupOwner (String groupID, String ks, String ksPass) throws IOException {

		String owner="";
		byte[] decripted= new byte[256];
		Key secretKey=getSecretKey(ks, ksPass);
		decripted=decryptFile(ks, ksPass, secretKey, GROUPINFOFILE);
		String []lines=new String(decripted).split("\n");
		String [] splitLine = new String [3];

		for(String line:lines) {
			splitLine = line.split(":");
			if (splitLine[0].equals(groupID)) {
				owner = splitLine[1];
			}
		}
		return owner;
	}




	public static void saveState(Serializable object, String fileName,String ks, String keyStorePass){
		try {
			byte[]followByte=new byte[256];
			Key secretKey=getSecretKey(ks, keyStorePass);
			File ficheiro=new File(fileName);			
			ByteArrayOutputStream b = new ByteArrayOutputStream();
			ObjectOutputStream o = new ObjectOutputStream(b);
			o.writeObject(object);
			followByte=b.toByteArray();
			encryptFile(ks, keyStorePass, followByte, secretKey, ficheiro);
					/*
			FileOutputStream fileOut = new FileOutputStream(fileName);
			ObjectOutputStream out = new ObjectOutputStream(fileOut);
			out.writeObject(object);
			out.close();
			fileOut.close();
					 */
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static Object loadState(String fileName, String ks, String ksPassword) {


		try {
			byte[] decripted=new byte[256];
			Key secretKey=getSecretKey(ks, ksPassword);
			File filename=new File(fileName);
			decripted=decryptFile(ks, ksPassword, secretKey, filename);
			ByteArrayInputStream in = new ByteArrayInputStream(decripted);
			ObjectInputStream is = new ObjectInputStream(in);
			return is.readObject();
			/*
			FileInputStream saveFile = new FileInputStream(fileName);
			ObjectInputStream in = new ObjectInputStream(saveFile);
			result = in.readObject();
			in.close();
			 */
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
		return null;
	}	

	private static String stringify(List<String> list, String delimitador) {

		String result = "";

		for (String l : list) {
			result+=l;
			if(list.indexOf(l)!=list.size()-1) { 
				result +=delimitador;
			}
		}
		return result;
	}

	public static byte[] wrap(KeyStore ks, String keyStore , String keyStorePass, Key secretKey) {
		try {

			Enumeration<String> aliases = ks.aliases();
			String alias = aliases.nextElement();
			Certificate cert = ks.getCertificate(alias);
			PublicKey key = cert.getPublicKey();

			Cipher c = Cipher.getInstance("RSA");
			c.init(Cipher.WRAP_MODE, key);
			byte []encoded = c.wrap(secretKey);
			return encoded;


		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] decryptFile( String keyStore , String keyStorePass,Key secretKey, File desFile) {
		try {
			FileInputStream userInputStream = new FileInputStream(desFile);
			//ObjectInputStream utilizadorInputStream = new ObjectInputStream(userInputStream);
			int size=(int) desFile.length();
			byte [] file=new byte[size];
			userInputStream.read(file);
			//utilizadorInputStream.close();
			userInputStream.close();

			KeyStore ks = KeyStore.getInstance("JCEKS");
			FileInputStream keyIS = new FileInputStream(keyStore);
			ks.load(keyIS, keyStorePass.toCharArray());

			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] unencriptedFile = cipher.doFinal(file);
			return unencriptedFile;	
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static boolean encryptFile(String keyStore , String keyStorePass, byte[] finalFileByte, Key secretKey, File toEncript) {
		try {

			KeyStore ks = KeyStore.getInstance("JCEKS");
			FileInputStream keyIS = new FileInputStream(keyStore);
			ks.load(keyIS, keyStorePass.toCharArray());
			Cipher cipher = Cipher.getInstance("AES");	
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] file = cipher.doFinal(finalFileByte);


			FileOutputStream fileWriter = new FileOutputStream(toEncript);
			//ObjectOutputStream objWriter= new ObjectOutputStream(fileWriter);
			fileWriter.write(file);
			//objWriter.close();
			fileWriter.close();



			return true;	

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}	


	}


	public static Key getSecretKey(String ks, String ksPass) {
		try {


			
			FileInputStream keyInputStream=new FileInputStream(USERFILEKEY);
			//ObjectInputStream objInputStream= new ObjectInputStream(keyInputStream);
			int size=(int) USERFILEKEY.length();
			byte[] keyEncoded=new byte[size];
			keyInputStream.read(keyEncoded);
			//objInputStream.close();
			keyInputStream.close();



			KeyStore store = KeyStore.getInstance("JCEKS");
			FileInputStream inputStream = new FileInputStream(ks);
			store.load(inputStream, ksPass.toCharArray());

			Enumeration<String> aliases = store.aliases();
			String alias = aliases.nextElement();



			Key privateKey = store.getKey(alias,ksPass.toCharArray());


			Cipher cipher = Cipher.getInstance("RSA");

			cipher.init(Cipher.UNWRAP_MODE, privateKey);
			Key secretKey = cipher.unwrap(keyEncoded, "AES", Cipher.SECRET_KEY);
			return secretKey;

		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}


