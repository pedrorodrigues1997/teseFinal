package crypto;

public class Aes256 {

    private long key;
    private String message;


    public Aes256(long key, String message) {
        this.key=key;
        this.message=message;
//TODO CREATRE CIPHER HERE
    }

    public Aes256 encrypt(){
        return null;//TODO
    }

    public String decrypt(long key, Aes256 cipher){
        return null;//TODO
    }
}