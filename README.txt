ATENÇÃO: ESTE README É RELATIVO À FASE1 DO PROJETO 1

Não houve limitações na realização do trabalho. Ainda assim, convém referir que, aquando a criação de um novo grupo, o seu nome não deve conter espaços.

Existem três formas de executar o projeto:

ATENÇÃO: A realização de todos estes comandos pressupõe que o utilizador se encontra no diretório SCProjeto1
 
COMPILAR OS FICHEIROS JAVA E CORRER OS SEUS EXECUTÁVEIS:

javac src/*.java (de forma a compilar todos os ficheiros .java)

Executar o Server sem SandBox:
java -cp src/ SeiTchizServer <port>
Executar o Server com SandBox: 
java -Djava.security.manager -Djava.security.policy=server.policy -cp src/ SeiTchizServer <port> 
Executar o cliente sem SandBox:
java -cp src/ SeiTchiz <ip:port> <username> <password>(se não for colocada uma port, esta é 45678, por default)
Executar o cliente com SandBox:
java -Djava.security.manager -Djava.security.policy=client.policy -cp src/ SeiTchiz <ip:port> <username> <password>
NOTA: A utilização da SandBox apenas permite ao client a utilização da port "45678"

ATRAVÉS DO ECLIPSE:

Abrir o IDE Eclipse
Importar o Projeto em questão
Na classe SeiTchizServer.java selecionar Run Configurations->Arguments, colocar uma <port> em "Program Arguments"
Colocar -Djava.security.manager -Djava.security.policy=server.policy em "Vm Arguments" se pretender correr o código numa SandBox
Clicar Apply e , de seguida, selecionar Run
Na classe SeiTchiz.java selecionar Run Configurations->Arguments, colocar uma <port> em "Program Arguments"
Colocar -Djava.security.manager -Djava.security.policy=client.policy em "Vm Arguments" se pretender correr o código numa SandBox
Clicar Apply e , de seguida, selecionar Run
NOTA: A utilização da SandBox apenas permite ao client a utilização da port "45678"

A PARTIR DOS FICHEIROS .JAR:

Executar o Server sem SandBox:
java -jar src/jars/SeiTchizServer.jar 45678
Executar o Server com SandBox: 
java -Djava.security.manager -Djava.security.policy=server.policy -jar src/jars/SeiTchizServer.jar <port>
Executar o cliente sem SandBox:
java  -jar src/jars/SeiTchiz.jar <ip:port> <username> <password>(se não for colocada uma port, esta é 45678, por default)
Executar o cliente com SandBox:
java -Djava.security.manager -Djava.security.policy=client.policy -jar  src/jars/SeiTchiz.jar <ip:port> <username> <password>

NOTA:A utilização da SandBox apenas permite ao client a utilização da port "45678"
	
