/**
 * Clase Usuario. 
 * Clase para almacenar los datos de un usuario.
 * 
 * @author Juan Carlos Cuevas Martínez, Alejandro Romo Rivero.
 **/
public class Usuario {
    private String nombre;
    private String apellido1;
    private String apellido2;
    private String nif;
    
   /**
     * Constructor de la clase Usuario.
     * 
     * @param n Nombre.
     * @param a1 Primer Apellido.
     * @param a2 Segundo Apellido.
     * @param ni DNI.
    **/
    public Usuario(String n,String a1,String a2,String ni){
        nombre=n;
        apellido1=a1;
        apellido2=a2;
        nif=ni;
    }
    
    /**
     * Metodo toString.
     * Sobreescribe el Metodo toString y devuelve los datos usuario como un String.
     * 
     * @return String con los datos del usuario (Nombre, Primer Apellido, Segundo Apellido, NIF).
    **/
    @Override
    public String toString(){
        return nombre+" "+apellido1+" "+apellido2+" "+nif;
    }

    /**
     * Metodo getNombre.
     * Metodo get para el Nombre del Usuario.
     * 
     * @return Cadena con nombre del usuario.
     **/
    public String getNombre() {
        return nombre;
    }

    /**
     * Metodo setNombre.
     * Metodo set para el Nombre del Usuario.
     * 
     * @param nombre que se quiere insertar.
     **/
    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    /**
     * Metodo getApellido1.
     * Metodo get para el Primer Apellido del Usuario.
     * 
     * @return Cadena con primer apellido del usuario.
    **/
    public String getApellido1() {
        return apellido1;
    }
    
    /**
     * Metodo setApellido1.
     * Metodo set para el Primer Apellido del Usuario.
     * 
     * @param apellido1 que se quiere insertar.
     **/
    public void setApellido1(String apellido1) {
        this.apellido1 = apellido1;
    }

    /**
     * Metodo getApellido2. 
     * Metodo get para el Segundo Apellido del Usuario.
     * 
     * @return Cadena con segundo apellido del usuario.
    **/
    public String getApellido2() {
        return apellido2;
    }

    /**
     * Metodo setApellido2.
     * Metodo set para el Segundo Apellido del Usuario.
     * 
     * @param apellido2 que se quiere insertar.
     **/
    public void setApellido2(String apellido2) {
        this.apellido2 = apellido2;
    }
    
    /**
     * Metodo getNif.
     * Metodo get para el Nif del Usuario.
     * 
     * @return Cadena con nif del usuario.
    **/
    public String getNif() {
        return nif;
    }
    
    /**
     * Metodo setNif.
     * Metodo set para el Nif del Usuario.
     * 
     * @param nif que se quiere insertar.
     **/
    public void setNif(String nif) {
        this.nif = nif;
    }
          
}
