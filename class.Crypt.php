<?php
class Crypt {
    
    public $mcryptOptions = Array();
    public $dataEncrypt = null;
    public $dataDecrypt = null;
    
    private $encryptErrorReport = "Faild encrypt";
    private $decryptErrorReport = "Faild decrypt";
    
    public $mcrptAlgorithmus = array(
        "blowfish" => MCRYPT_BLOWFISH,
        "tripledes" => MCRYPT_TRIPLEDES,
        "rjindael-256" => MCRYPT_RIJINDAEL_256,
        "cast-256" => MCRYPT_CAST_256
    );                                       
    public $mcrptMode = array(
        "ecb" => MCRYPT_MODE_ECB,
        "cbc" => MCRYPT_MODE_CBC,
        "cfb" => MCRYPT_MODE_CFB,
        "nofb" => MCRYPT_MODE_NOFB,
        "stream" => MCRYPT_MODE_STREAM
    );        

    public function __construct( $algorithmus, $modus, $password ) {
        if( array_key_exists( $modus, $this->mcrptMode ) && array_key_exists( $algorithmus, $this->mcrptAlgorithmus) ) {
            $this->mcryptOptions['algorithmus'] = $this->mcrptAlgorithmus[strtolower( $algorithmus )];
            $this->mcryptOptions['modus'] = $this->mcrptMode[strtolower( $modus )];
            $this->mcryptOptions['initialisierung'] = $this->createIV(); 
            $this->mcryptOptions['passwordSize'] = $this->getKeySize();
            $this->mcryptOptions['Password'] = (empty($password))? $this->getRandomString() : $password ;
        } else {
            throw new \InvalidArgumentException( "Unknown algorithm/mode." );
        }
    }
    
     public function getInformation() {
        var_dump( $this->mcryptOptions );
    }


    private function createIV() {
        $iv_length = mcrypt_get_iv_size( $this->mcryptOptions['algorithmus'], $this->mcryptOptions['modus']);
        return mcrypt_create_iv( $iv_length, MCRYPT_RAND );
    }



    private function getKeySize() {
        return mcrypt_get_key_size( $this->mcryptOptions['algorithmus'],$this->mcryptOptions['modus']);
    }
    

    private function getRandomString() {
        $InsaliesierungsString = "0123456789abcedfghijklmnopqrstvwxyzABCDEFGHIJKLMNOPQRSTVWXYZ!§$%&/=+*-><#";
        $ISLenght = strlen($InsaliesierungsString);
  
        for ($i = 0; $i != $this->mcryptOptions['passwordSize'] ; $i++){
            $key .= $InsaliesierungsString{mt_rand(0,$ISLenght)};
        }
        return $key;
    }
    
    public function encrypt( $data ) {
        if( !empty( $data ) ) {
          if($this->dataEncrypt = mcrypt_encrypt( $this->mcryptOptions['algorithmus'], $this->mcryptOptions['Password'], $data, $this->mcryptOptions['modus'],$this->mcryptOptions['initialisierung'])){
              throw new Exception($this->encryptErrorReport);
          }
        }
    }

    public function decrypt( $data ) {
        if( !empty( $data ) ) {
            if(!$this->dataDecrypt = mcrypt_decrypt( $this->mcryptOptions['algorithmus'], $this->mcryptOptions['Password'], $data, $this->mcryptOptions['modus'], $this->mcryptOptions['initialisierung'] )){
                 throw new Exception($this->decryptErrorReport);
            }
        }
    }

}