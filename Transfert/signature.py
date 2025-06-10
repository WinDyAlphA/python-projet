from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding



def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key
def generate_public_key(private_key):
    public_key = private_key.public_key()
    return public_key

def export_keys(private_key, public_key):
  private_pem = private_key.private_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PrivateFormat.PKCS8,
  encryption_algorithm=serialization.NoEncryption()
  )
  public_pem = public_key.public_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PublicFormat.SubjectPublicKeyInfo
  )
  return private_pem, public_pem

def sign_message(private_key, message):
  signature = private_key.sign(
    message,
    padding.PSS(
      mgf=padding.MGF1(hashes.SHA256()),
      salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
  )
  return signature

def verify_message(public_key, message, signature):
  try:
    public_key.verify(
      signature,
      message,  
      padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH),
      hashes.SHA256()
    )
    return True
  except Exception as e:
    return False

def verify_file_signature(file_path, signature_path, public_key):
  """
  Vérifie la signature d'un fichier
  
  Args:
      file_path (str): Chemin vers le fichier à vérifier
      signature_path (str): Chemin vers le fichier de signature
      public_key: Clé publique pour la vérification
      
  Returns:
      bool: True si la signature est valide, False sinon
  """
  try:
    # Lire le contenu du fichier
    with open(file_path, "rb") as file:
      message = file.read()
    
    # Lire la signature
    with open(signature_path, "rb") as sig_file:
      signature = sig_file.read()
    
    # Vérifier la signature
    return verify_message(public_key, message, signature)
  except Exception as e:
    print(f"Erreur lors de la vérification: {str(e)}")
    return False

def generate_keys():
   private_key = generate_private_key()
   public_key = generate_public_key(private_key)
   private_pem, public_pem = export_keys(private_key, public_key)
   return private_key, public_key, private_pem, public_pem

def sign_for_send(file_path):
  private_key, public_key, private_pem, public_pem = generate_keys()

  #print("Clé privée: \n", private_pem.decode())
  #print("Clé publique: \n", public_pem.decode())
  
  # Sauvegarder la clé publique pour vérification ultérieure
  with open(file_path + ".pub", "wb") as pub_file:
    pub_file.write(public_pem)
  print(f"Clé publique sauvegardée dans {file_path}.pub")

  # Lire le contenu du fichier
  try:
    with open(file_path, "rb") as file:
      message = file.read()
    print(f"Message lu depuis {file_path}: {message.decode() if len(message) < 100 else message.decode()[:100] + '...'}")
    
    # Signer le message
    signature = sign_message(private_key, message)
    print("Signature générée")
    
    # Sauvegarder la signature dans un fichier
    with open(file_path+".sig", "wb") as sig_file:
      sig_file.write(signature)
    print(f"Signature sauvegardée dans {file_path}.sig")
    
    return public_key
    
  except FileNotFoundError:
    print(f"Erreur: Le fichier {file_path} n'existe pas. Veuillez créer ce fichier avant d'exécuter le script.")
  except Exception as e:
    print(f"Erreur lors de la signature: {str(e)}")
  
  return None

def load_public_key(public_key_path):
  """
  Charge une clé publique depuis un fichier PEM
  
  Args:
      public_key_path (str): Chemin vers le fichier de clé publique (.pub)
      
  Returns:
      La clé publique chargée ou None en cas d'erreur
  """
  try:
    with open(public_key_path, "rb") as key_file:
      public_pem = key_file.read()
      
    public_key = serialization.load_pem_public_key(public_pem)
    return public_key
  except Exception as e:
    print(f"Erreur lors du chargement de la clé publique: {str(e)}")
    return None
  