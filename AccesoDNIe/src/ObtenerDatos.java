import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.*;

/**
 * La clase ObtenerDatos implementa cuatro metodos publicos que permiten obtener
 * determinados datos de los certificados de tarjetas DNIe, Izenpe y Ona.
 *
 * @author Juan Carlos Cuevas Martínez, Alejandro Romo Rivero.
 **/
public class ObtenerDatos {

    private static final byte[] dnie_v_1_0_Atr = {
        (byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x44,
        (byte) 0x4E, (byte) 0x49, (byte) 0x65, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x00};
    private static final byte[] dnie_v_1_0_Mask = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF};

    public ObtenerDatos() {
    }
    
    /**
     * Metodo empleado para poder leer DNIe.
     * 
     * @return Usuario que ha sido leido del DNIe. 
     **/
    public Usuario LeerNIF() {

        Usuario user = null;
        byte[] datos=null;
        
        try {
            Card c = ConexionTarjeta();
            if (c == null) {
                throw new Exception("ACCESO DNIe: No se ha encontrado ninguna tarjeta");
            }
            byte[] atr = c.getATR().getBytes();
            CardChannel ch = c.getBasicChannel();

            if (esDNIe(atr)) {
                datos = leerCertificado(ch); //Se lee el certificado. 
                if(datos!=null)              //Si hay datos del certificado. 
                    user = leerDatosUsuario(datos); //Metodo que devuelve el objeto usuario junto con sus datos que han sido leidos.
            }
            c.disconnect(false);

        } catch (Exception ex) {
            Logger.getLogger(ObtenerDatos.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
        return user;
    }

   /**
     * Metodo para leer el certificado del DNIe.
     * 
     * @param ch Canal de envio de la informacion hacia DNIe.
     * @return Los datos en bytes a transmitir.
   **/
    public byte[] leerCertificado(CardChannel ch) throws CardException, CertificateException {


        int offset = 0;
        String completName = null;

        /*[1] PRACTICA 3. Punto 1.a
        * Comando SELECT.
        * Este comando permite la seleccion de fichero dedicado (DF) o de un fichero elemental (EF).
        * Codificacion del Comando:
        ** CLA  = 0x00;
        ** INS  = 0xa4;
        ** P1   = 0x04; "Seleccion directa de DF por nombre."
        ** P2   = 0x00; 
        ** LC   = 0x0b; "Longitud de los datos."
        ** DATA = 0x4D 0x61 0x73 0x74 0x65 0x72 0x2E 0x46 0x69 0x6C 0x65; "Datos de acuerdo a P1-P2."
        ** LE   = Vacio;
        *** Para este caso y analizando los campos anteriores se puede apreciar que se selecciona
        *** el fichero dedicado (DF) "P1 = 0x04". y que la Longitud de los datos = 0b (HEX)
        *** lo cual indica 0000 1011 (BIN) y que indica que la Longitud de los datos será de 11 bytes (DEC).
        */
        byte[] command = new byte[]{(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, (byte) 0x4D, (byte) 0x61, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x2E, (byte) 0x46, (byte) 0x69, (byte) 0x6C, (byte) 0x65};
        ResponseAPDU r = ch.transmit(new CommandAPDU(command));
        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        }

        /*[2] PRACTICA 3. Punto 1.a
        * Comando SELECT.
        * Este comando permite la seleccion de fichero dedicado (DF) o de un fichero elemental (EF).
        * Codificacion del Comando:
        ** CLA  = 0x00;
        ** INS  = 0xA4;
        ** P1   = 0x00; "Selecciona DF o EF por Id (data field = id)."
        ** P2   = 0x00; 
        ** LC   = 0x02; "Longitud de los datos."
        ** DATA = 0x50 0x15; "Datos de acuerdo a P1-P2."
        ** LE   = Vacio;
        *** Para este caso y analizando los campos anteriores se puede apreciar que se selecciona
        *** el fichero dedicado (DF) por Id "P1 = 0x00". Y que la Longitud de datos = 02 (HEX) lo cual
        *** indica 0000 0010 (BIN) y que indica que la Longitud de los datos será de 2 bytes (DEC). Y, 
        *** en datos se puede encontrar que se seleccionará por Id el "0x50 0x15".
        */
        command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x50, (byte) 0x15};
        r = ch.transmit(new CommandAPDU(command));

        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        }

        /*[3] PRACTICA 3. Punto 1.a
        * Comando SELECT.
        * Este comando permite la seleccion de fichero dedicado (DF) o de un fichero elemental (EF).
        * Codificacion del Comando:
        ** CLA  = 0x00;
        ** INS  = 0xA4;
        ** P1   = 0x00; "Selecciona DF o EF por Id (data field = id)."
        ** P2   = 0x00; 
        ** LC   = 0x02; "Longitud de los datos."
        ** DATA = 0x60 0x04; "Datos de acuerdo a P1-P2."
        ** LE   = Vacío;
        *** Para este caso y analizando los campos anteriores se puede apreciar que se selecciona
        *** el fichero dedicado (DF) por Id "P1 = 0x00". Y que la Longitud de datos = 02 (HEX) lo cual
        *** indica 0000 0010 (BIN) y que indica que la Longitud de los datos será de 2 bytes (DEC). Y, 
        *** en datos se puede encontrar que se seleccionará por Id el "0x60 0x04".
        */ 
        command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x60, (byte) 0x04};
        r = ch.transmit(new CommandAPDU(command));

        byte[] responseData = null;
        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        } else {
            responseData = r.getData();
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] r2 = null;
        int bloque = 0;

        do {
             //[4] PRACTICA 3. Punto 1.b
            /*Comando READ BINARY.
             * Devuelve en su mensaje de respuesta el contenido (o parte) de un fichero elemental transparente.
             * Codificación del Comando:
             ** CLA  = 0x0X -> 0x00; "Este valor me indicara la clase, en este caso 0x00 No SM (Secure messaging) or no SM indication."
             ** INS  = 0xB0; 
             ** P1   = 0x00; "Selecciona DF o EF por Id (data field = id)."
             ** P2   = 0x00; 
             ** LC   = Vacio; 
             ** DATA = Vacio; 
             ** LE   = ; "Numero de Bytes a leer."
             */
            final byte CLA = (byte) 0x00;//Buscar qué valor poner aquí (0xFF no es el correcto) 
            final byte INS = (byte) 0xB0;//Buscar qué valor poner aquí (0xFF no es el correcto)
            final byte LE = (byte) 0xFF;// Identificar qué significa este valor.

            //[4] PRACTICA 3. Punto 1.b
            //P1 y P2 indican el offset del primer byte a leer desde el principio del fichero.
            //Siendo P1 el "MSB" y P2 el "LSB".
            command = new byte[]{CLA, INS, (byte) bloque/*P1*/, (byte) 0x00/*P2*/, LE};//Identificar qué hacen P1 y P2
            r = ch.transmit(new CommandAPDU(command));
            //System.out.println("ACCESO DNIe: Response SW1=" + String.format("%X", r.getSW1()) + " SW2=" + String.format("%X", r.getSW2()));

            if ((byte) r.getSW() == (byte) 0x9000) {
                r2 = r.getData();

                baos.write(r2, 0, r2.length);

                for (int i = 0; i < r2.length; i++) {
                    byte[] t = new byte[1];
                    t[0] = r2[i];
                    System.out.println(i + (0xff * bloque) + String.format(" %2X", r2[i]) + " " + String.format(" %d", r2[i])+" "+new String(t));
                }
                bloque++;
            } else {
                return null;
            }

        } while (r2.length >= 0xfe);


         ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

      

        
        return baos.toByteArray();
    }

    
    
    
    /**
     * Este metodo establece la conexion con la tarjeta. La funcion busca el
     * Terminal que contenga una tarjeta, independientemente del tipo de tarjeta
     * que sea.
     *
     * @return objeto Card con conexion establecida
     * @throws Exception
     */
    private Card ConexionTarjeta() throws Exception {

        Card card = null;
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        //System.out.println("Terminals: " + terminals);

        for (int i = 0; i < terminals.size(); i++) {

            // get terminal
            CardTerminal terminal = terminals.get(i);

            try {
                if (terminal.isCardPresent()) {
                    card = terminal.connect("*"); //T=0, T=1 or T=CL(not needed)
                }
            } catch (Exception e) {

                System.out.println("Exception catched: " + e.getMessage());
                card = null;
            }
        }
        return card;
    }

    /**
     * Este metodo nos permite saber el tipo de tarjeta que estamos leyendo del
     * Terminal, a partir del ATR de esta.
     *
     * @param atrCard ATR de la tarjeta que estamos leyendo
     * @return tipo de la tarjeta. 1 si es DNIe, 2 si es Starcos y 0 para los
     * demas tipos
     */
    private boolean esDNIe(byte[] atrCard) {
        int j = 0;
        boolean found = false;

        //Es una tarjeta DNIe?
        if (atrCard.length == dnie_v_1_0_Atr.length) {
            found = true;
            while (j < dnie_v_1_0_Atr.length && found) {
                if ((atrCard[j] & dnie_v_1_0_Mask[j]) != (dnie_v_1_0_Atr[j] & dnie_v_1_0_Mask[j])) {
                    found = false; //No es una tarjeta DNIe
                }
                j++;
            }
        }

        if (found == true) {
            return true;
        } else {
            return false;
        }

    }

    /**
     * Analizar los datos leidos del DNIe para obtener:
     *   - nombre: OID 85 4 42
     *   - apellidos y nombre: OID 85 4 3
     *   - NIF del DNI: OID 85 4 5
     * Los valores del OID han sido extraidos del excel aportado para el desarrollo 
     * de la practica, y con esos valores del OID se sacara el nombre, los apellidos
     * y el NIF del DNIe. 
     * @param datos
     * @return Objeto de clase Usuario con los datos asociados extraidos del DNIe.
     */
    private void leerDatosUsuario(byte[] datos) {
        //Variables del metodo.

    }
}
