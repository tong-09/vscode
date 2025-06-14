from os import system
def main():
  system('sudo apt-get install -y python3-pip')
  system('pip3 install requests colorama')
if __name__ == '__main__':
  main()
