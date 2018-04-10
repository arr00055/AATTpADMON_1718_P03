import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;


/**
 * Aplicaciones Telemáticas para la Administración
 * 
 * Este programa debe ller el nombre y NIF de un usuario del DNIe, formar el identificador de usuario y autenticarse con un servidor remoto a través de HTTP 
 * @author Juan Carlos Cuevas Martínez, Alejandro Romo Rivero. 
 */
public class Main {
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception{
        ByteArrayInputStream bais=null;
        String usuario;
        String clave;
        //TAREA 2. Conseguir que el método LeerNIF de ObtenerDatos devuelva el 
        //         correctamente los datos de usuario 
        ObtenerDatos od = new ObtenerDatos();
        Usuario user = od.LeerNIF();
        if(user!=null)
        /*Si existe el usuario se procedera a realizar un saludo de bienvenida mostrando su nombre, apellidos y nif.*/
         System.out.println("Bienvenido: "+user.getApellido1()+" "+user.getApellido2()+" "+user.getNombre()+" Con NIF: "+user.getNif());
        /**
         * Obtencion de la clave y usuario del cliente que empleara para la autentificacion en el servidor Http. 
         **usuario: El valor de este parametro sera una cadena de texto formada por: 
         ***Inicial del nombre.
         ***Primer apellido. 
         ***Inicial del segundo apellido.
         **clave: El valor de este parametro sera el nif del usuario. 
         */
        usuario = user.getNombre().charAt(0)+user.getApellido1()+user.getApellido2().charAt(0);
        System.out.println("Tu usuario sera: "+usuario);
        clave = user.getNif();
        System.out.println("Tu clave sera: "+clave);
        //TAREA 3. AUTENTICAR EL CLIENTE CON EL SERVIDOR
        
    }
}
