package EncryptionTools; /**
 * Materiais/Labs para SRSC 17/18, Sem-2
 * Henrique Domingos, 12/3/17
 **/

import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
public class ListAlgorithms
{

    /** 
     * Imprime set de entries - indentando um por linha, com o nome do set
     * nao indentado na primeira linha
     * 
     * @param setName : nome do set a imprimir
     * @param algorithms : set de algoritmos associado ao nome dado
     */
    public static void printSet(
        String setName,
        Set<String> algorithms)

    {
        System.out.println("----------------------------------------------------");
        System.out.println(setName);
        System.out.println("----------------------------------------------------");
        
        if (algorithms.isEmpty())
        {
	    System.out.println("------------------------------------------------");
            System.out.println("            None available.");
	    System.out.println("------------------------------------------------");
        }
        else
        {
            Iterator<?>	it = algorithms.iterator();
            
            while (it.hasNext())
            {
                String	name = (String)it.next();
                
                System.out.println("  " + name);
            }
        }
    }
    
    /**
     * List the available algorithm names for ciphers, key agreement, macs,
     * message digests and signatures.
     */
    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());
        Provider[] providers = Security.getProviders();
        Set<String>        ciphers = new HashSet<String>();
        Set<String>        keyAgreements = new HashSet<String>();
        Set<String>        macs = new HashSet<String>();
        Set<String>        messageDigests = new HashSet<String>();
        Set<String>       signatures = new HashSet<String>();
        
        for (int i = 0; i != providers.length; i++)
        {
            Iterator<?> it = providers[i].keySet().iterator();
            while (it.hasNext())
            {
                String	entry = (String)it.next();
                
                if (entry.startsWith("Alg.Alias."))
                {
                    entry = entry.substring("Alg.Alias.".length());
                }
                
                if (entry.startsWith("Cipher."))
                {
                    ciphers.add(entry.substring("Cipher.".length()));
                }
                else if (entry.startsWith("KeyAgreement."))
                {
                    keyAgreements.add(entry.substring("KeyAgreement.".length()));
                }
                else if (entry.startsWith("Mac."))
                {
                    macs.add(entry.substring("Mac.".length()));
                }
                else if (entry.startsWith("MessageDigest."))
                {
                    messageDigests.add(entry.substring("MessageDigest.".length()));
                }
                else if (entry.startsWith("Signature."))
                {
                    signatures.add(entry.substring("Signature.".length()));
                }
            }
        }
        
        printSet("Ciphers (Alg.): ", ciphers);
        printSet("KeyAgreeents: ", keyAgreements);
        printSet("MACs: ", macs);
        printSet("MessageDigests (Secure Hash-Functions): ", messageDigests);
        printSet("Signatures (Digital Sigantures w/ PubKey Methods) :", signatures);
    }
}


