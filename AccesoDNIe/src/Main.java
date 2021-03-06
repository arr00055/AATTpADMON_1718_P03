import java.io.*;
import java.net.*;
import java.util.*;

/**
 * Clase Main. 
 * Aplicaciones Telemáticas para la Administración.
 * 
 * Este programa debe ller el nombre y NIF de un usuario del DNIe, formar el identificador de usuario y autenticarse con un servidor remoto a través de HTTP. 
 * @author Juan Carlos Cuevas Martínez, Alejandro Romo Rivero. 
 */
public class Main {

    /**
     * Metodo void main. 
     * @param args the command line arguments
     * @throws java.lang.Exception
     */
    public static void main(String[] args) throws Exception{
        //TAREA 2. Conseguir que el método LeerNIF de ObtenerDatos devuelva el 
        //         correctamente los datos de usuario. 
        ObtenerDatos od = new ObtenerDatos();
        Usuario user = od.LeerNIF();
        
        if(user!=null){
        /*Si existe el usuario se procedera a realizar un saludo de bienvenida mostrando su nombre, apellidos y nif.*/
        System.out.println("Bienvenido: "+user.getApellido1()+" "+user.getApellido2()+" "+user.getNombre()+" Con NIF: "+user.getNif());
        /**
         * Obtencion de la clave y usuario del cliente que empleara para la autentificacion en el servidor HTTP. 
         **usuario: El valor de este parametro sera una cadena de texto formada por: 
         ***Inicial del nombre.
         ***Primer apellido. 
         ***Inicial del segundo apellido.
         **clave: El valor de este parametro sera el nif del usuario. 
         */
        String usuario = user.getNombre().charAt(0)+user.getApellido1()+user.getApellido2().charAt(0);
        //Se informa del usuario que empleara el cliente para la autentificacion con el servidor.
        System.out.println("Tu usuario sera: "+usuario);
 
        String clave = user.getNif();
        //Se informa de la clave que empleara el cliente para la autentificacion con el servidor.
        System.out.println("Tu clave sera: "+clave);
        
        //TAREA 3. AUTENTICAR EL CLIENTE CON EL SERVIDOR.
        
        /*Se tomara la direccion IP del equipo, pues para la practica se considera que cliente y servidor estan en el mismo
          equipo para su uso.*/
        InetAddress localHost = InetAddress.getLocalHost();
        //System.out.println(localHost.getHostAddress());
        String direccionIp = localHost.getHostAddress();
        
        /*Se fijara el puerto empleado como una variable por si fuera necesaria su modificacion.*/
        String puertoServicio = "8080";
        
        //Se llama al metodo autenticar encargado de realizar la conexion HTTP con el servidor y dar la respuesta correcta o
        //incorrecta en funcion de los valores que se le pasen al metodo.
        if(usuario.equals("")||clave.equals("")){
            System.out.println("Hay un problema con el usuario y/o la clave.");
        }else{
             autenticar(direccionIp,puertoServicio,usuario,clave);
        }
        
       }//Fin del if que comprueba que usuario no sea null. 
    }//Fin del static void main.
    
    /**
     * Metodo autenticar.
     * Metodo utilizado para enviar la peticion POST al servidor y recibir la respuesta de este en caso de que 
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
        /*Creo un Map params al que insertar por orden los Strings asociados entre si.*/
        Map<String, Object> params = new LinkedHashMap<>();
        
        //Metodo put empleado para colocar con key "usuario" el usuario. 
        params.put("usuario", usser);
        //Metodo put empleado para colocar con key "clave" la clave. 
        params.put("clave", key);
        
        //Secuencia de caracteres mutable se usa en lugar del StringBuffer. 
        StringBuilder postDatos = new StringBuilder();
        /**
         * Entrada del mapa que me devuelve una coleccion de vistas del Map de la 
         * coleccion creada anteriormente y crea un conjunto de vistas del Map.
         * 
         * Se recorre con un bucle for para ello, y luego se debe comprobar que 
         * la longitud es distinta de cero en cuyo caso se procede a concatenar 
         * con append los strings almacenados para luego enviar estos en la 
         * peticion y luego codificar la peticion HTTP con UTF-8.
        */
        for (Map.Entry<String, Object> param : params.entrySet()) {
            
            if (postDatos.length() != 0)
                postDatos.append('&');
            postDatos.append(URLEncoder.encode(param.getKey(), "UTF-8"));
            postDatos.append('=');
            postDatos.append(URLEncoder.encode(String.valueOf(param.getValue()),"UTF-8"));
        }
        
        //Array de tipo byte para convertir los Strings en un array de bytes UTF-8.
        byte[] postDataBytes = postDatos.toString().getBytes("UTF-8");
        
        /**
         * Objeto conn para poder realizar la peticion de tipo POST. Se definen 
         * los diferentes parametros de la peticion para el tipo del contenido 
         * asi como el buffer y flujo de salida de datos en el cual se coloca
         * el array de bytes con la peticion a realizar. 
        */
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type","application/x-www-form-urlencoded");
        conn.setRequestProperty("Content-Length",
        String.valueOf(postDataBytes.length));
        conn.setDoOutput(true);
        conn.getOutputStream().write(postDataBytes);
        
        /**
         * Se define el buffer de entrada para leer los datos que seran la respuesta
         * a la peticion POST realizada al servidor y que contara con la respuesta
         * correcta o incorrecta, es importante que la codificacion sea la misma 
         * para poder leer adecuadamente los datos. 
         */
        Reader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
        
        //Recorro el indice del buffer de entrada y voy mostrando como caracter los valores para cada uno. 
        for (int lectura = in.read(); lectura != -1; lectura = in.read()){
            System.out.print((char) lectura); 
        }
         
        //Excepciones que puedan producirse por algun problema a raiz de la conexion o la URL. 
        } catch (MalformedURLException e) {
            System.out.println("Problema en la URL: " + e.getMessage());
        } catch (IOException e) {
            System.out.println("Error de conexion: " + e.getMessage());
        }
        
    }//Fin del metodo autenticar.
}//Fin de la clase main.
