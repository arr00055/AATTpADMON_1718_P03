import java.io.*;
import java.net.*;
import java.util.*;

/**
 * Aplicaciones Telemáticas para la Administración
 * 
 * Este programa debe ller el nombre y NIF de un usuario del DNIe, formar el identificador de usuario y autenticarse con un servidor remoto a través de HTTP 
 * @author Juan Carlos Cuevas Martínez, Alejandro Romo Rivero. 
 */
public class Main {

    /**
     * @param args the command line arguments
     * @throws java.lang.Exception
     */
    public static void main(String[] args) throws Exception{
        //TAREA 2. Conseguir que el método LeerNIF de ObtenerDatos devuelva el 
        //         correctamente los datos de usuario 
        ObtenerDatos od = new ObtenerDatos();
        Usuario user = od.LeerNIF();
        if(user!=null){
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
        String usuario = user.getNombre().charAt(0)+user.getApellido1()+user.getApellido2().charAt(0);
        System.out.println("Tu usuario sera: "+usuario);
        String clave = user.getNif();
        System.out.println("Tu clave sera: "+clave);
        
        //TAREA 3. AUTENTICAR EL CLIENTE CON EL SERVIDOR.
        
        /*Se tomara la direccion IP del equipo, pues para la practica se considera que cliente y servidor estan en el mismo
          equipo para su uso.*/
        InetAddress localHost = InetAddress.getLocalHost();
        //System.out.println(localHost.getHostAddress());
        String direccionIp = localHost.getHostAddress();
        
        /*Se fijara el puerto empleado como una variable por si fuera necesaria su modificacion.*/
        String puertoServicio = "8080";
        
        autenticar(direccionIp,puertoServicio,usuario,clave);
        
       }//Fin del if que comprueba que usuario no sea null. 
    }//Fin del static void main.
    
    /**
     * Metodo autenticar utilizado para enviar la peticion POST al servidor y recibir la respuesta de este en caso de que 
     * el usuario haya sido identificado o no. 
     * @param dirIP direccion IP del equipo donde se encuentra el servidor que es tomada automaticamente. 
     * @param portServ puerto en el que escucha las peticiones el servidor. 
     * @param usser usuario asignado a partir del DNIe.
     * @param key clave asignada al usuario a partir del DNIe. 
     * @throws MalformedURLException 
     */
    public static void autenticar(String dirIP,String portServ, String usser, String key) throws MalformedURLException{
        /*Se establece la URL donde se encuentra localizado el servidor, siguiendo el formato adecuado para ello.*/
        String urlhttp = "http://"+dirIP+":"+portServ+"/servidor/Login";
        URL url = new URL(urlhttp);
        
        /*Se establece el Try-Catch necesario para en caso de que se produzca algun error la aplicacion pueda llegar a 
          ejecutarse y se sepa cual es el problema acontecido.*/
        try{
        /**/
        Map<String, Object> params = new LinkedHashMap<>();
 
        params.put("usuario", usser);
        params.put("clave", key);
 
        StringBuilder postData = new StringBuilder();
        
        for (Map.Entry<String, Object> param : params.entrySet()) {
            
            if (postData.length() != 0)
                postData.append('&');
            postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
            postData.append('=');
            postData.append(URLEncoder.encode(String.valueOf(param.getValue()),"UTF-8"));
        }
        
        byte[] postDataBytes = postData.toString().getBytes("UTF-8");
 
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type","application/x-www-form-urlencoded");
        conn.setRequestProperty("Content-Length",
        String.valueOf(postDataBytes.length));
        conn.setDoOutput(true);
        conn.getOutputStream().write(postDataBytes);
        
        Reader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
        
        for (int c = in.read(); c != -1; c = in.read()){
            System.out.print((char) c); 
        }
           
        } catch (MalformedURLException e) {
            System.out.println("Problema en la URL: " + e.getMessage());
        } catch (IOException e) {
            System.out.println("Error de conexion: " + e.getMessage());
        }
        
    }
}//Fin de la clase main.
