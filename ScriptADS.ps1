# Equipo de laboratorio:
#
# Autores:
# Script PowerShell para practica de ADS

###################################################
#################### Funciones ####################
###################################################

# Crear una Unidad Organizativa
function Crea_Unidad ([String]$NombreUnidad, [String]$ruta) {
    New-ADOrganizationalUnit $NombreUnidad -Path $ruta -ProtectedFromAccidentalDeletion:$false -PassThru
    Write-Host "Unidad organizativa $NombreUnidad creada en $ruta"
}

# Añadir grupos globales a grupos locales
function anadirGlobalALocal ([String]$gr, [String]$miembro) {
    Add-ADGroupMember -Identity $gr  -Members $miembro
    Write-Host "Grupo $miembro añadido como miembro del grupo $gr"
}

# Crear los grupos globales
function crearGrupoGlobal ([String]$gr, [String]$ruta) {
    New-ADGroup -Name $gr -SamAccountName $gr -GroupCategory Security -GroupScope Global  -Path $ruta
    Write-Host "Grupo global $gr creado en $ruta"
}

# Crear los grupos de dominio local
function crearGrupoLocal ([String]$gr, [String]$ruta) {
    New-ADGroup -Name $gr -SamAccountName $gr -GroupCategory Security -GroupScope DomainLocal -Path $ruta
    Write-Host "Grupo de dominio local $gr creado en $ruta"
}

# Activar/desactivar la herencia en un directorio
function Set-Inheritance ([System.IO.DirectoryInfo]$folder, [Boolean]$inherit) {

    # Activa la herencia en $folder si $inherit es $true, la desactiva si $inherit es $false
    $acl = $folder.GetAccessControl()
    $acl.SetAccessRuleProtection($true, $inherit)
    $folder.SetAccessControl($acl)

    if ($inherit -eq $false) {
        Write-Host "Se ha deshabilitado la herencia para la carpeta $folder"
    } else {
        Write-Host "Se ha habilitado la herencia para la carpeta $folder"
    }
}

# Permisos de grupos en directorios
function Add-Ace ([System.IO.DirectoryInfo]$folder, [String]$group, [String]$permission) {

    $acl = $folder.GetAccessControl()
    $sid = (Get-ADGroup -filter { name -eq $group }).sid

    $rights = [System.Security.AccessControl.FileSystemRights]$permission
    $inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagationFlag = [System.Security.AccessControl.PropagationFlags]'None'
    $type =[System.Security.AccessControl.AccessControlType]'Allow'

    $ace = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ($sid, $rights, $inheritanceFlag, $propagationFlag, $type)

    $acl.AddAccessRule($ace)
    $folder.SetAccessControl($acl)

    Write-Host "Permiso concedido al grupo $group en la carpeta $folder"
}

# Procesar fichero CSV
function Procesa ($linea) {
	[string]$usu = $linea.usuario
	[string]$rol = $linea.rol
	[string]$proy = $linea.proyecto

	Write-Host "" # Salto de línea
    Write-Host "Procesando la linea: Usuario=$usu, Rol=$rol, Proyecto=$proy"

    # Comprobar si no existe algún parámetro en la línea.
    # Si faltase alguno, la línea no es válida y hay que pasar a la siguiente
    $error = ""
    if (-not $linea.usuario) {
        $error += "No se ha especificado el usuario"
    }
    if (-not $linea.rol) {
        $error += "No se ha especificado el rol"
    }
    if (-not $linea.proyecto) {
        if ($error -ne "") {
            $error += " ni tampoco el proyecto"
        } else {
            $error += "No se ha especificado el proyecto"
        }
    }
    if ($error -ne "") {
        Write-Host "$error. Línea anulada."
        return
    }

    # Cambio de nombre de roles
    $rolCorrecto = switch ($rol) {
        "Responsable" {"Responsable"}
        "Investigador" {"Investigador"}
        "Revisor" {"Revisor"}
    }

    # Si un usuario tiene un rol diferente a Responsable, Investigador o Revisor, el rol no es válido
    if (-not $rolCorrecto) {
        Write-Host "El rol $rol no existe. Línea anulada."
        return
    }

    $grResponsable = "$proy-Responsable"
    $grInvestigador = "$proy-Investigador"
    $grRevisor = "$proy-Revisor"

    $grCompleto = "ACL-$proy-Completo"
    $grModificacion = "ACL-$proy-Modificacion"
    $grLectura = "ACL-$proy-Lectura"

    # Creamos el proyecto $proy si no existía antes
    $carpeta = "C:\Proy-Temp\$proy"

    if (Test-Path $carpeta) {
        Write-Host "El proyecto $proy ya había sido creado"
    } else {
        $carpeta = New-Item $carpeta -itemType "Directory"
        Write-Host "Creando el nuevo proyecto $proy"

        # Si no existía el proyecto, creamos los 3 grupos del proyecto en OU=Roles
        crearGrupoGlobal -gr $grResponsable -ruta $pathRoles
        crearGrupoGlobal -gr $grInvestigador -ruta $pathRoles
        crearGrupoGlobal -gr $grRevisor -ruta $pathRoles

        # Creamos los grupos de dominio local para los recursos
        crearGrupoLocal -gr $grCompleto -ruta $pathRecursos
        crearGrupoLocal -gr $grModificacion -ruta $pathRecursos
        crearGrupoLocal -gr $grLectura -ruta $pathRecursos

        # Añadir grupos globales a los grupos locales correspondientes Responsable -> Completo, Revisores -> Lectura, Investigación -> Modificacion
        # El grupo Admins. del dominio tiene acceso completo al proyecto
        anadirGlobalALocal -gr $grCompleto -miembro "Admins. del dominio"
        anadirGlobalALocal -gr $grCompleto -miembro $grResponsable
        anadirGlobalALocal -gr $grModificacion -miembro $grInvestigadores
        anadirGlobalALocal -gr $grLectura -miembro $grRevisores

        # Asignamos los permisos a la carpeta del proyecto
        # El grupo Administradores tiene control total del proyecto
        # Deshabilitamos la herencia de la carpeta del proyecto
        Set-Inheritance -folder $carpeta -inherit $false # Deshabilitamos la herencia
        Add-ACE -folder $carpeta -group "Administradores" -permission "FullControl"
        Add-ACE -folder $carpeta -group $grCompleto -permission "FullControl"
        Add-ACE -folder $carpeta -group $grModificacion -permission "Modify"
        Add-ACE -folder $carpeta -group $grLectura -permission "Read"
    }

    # Creamos el usuario $usu si no existía antes
    $existeUsu = Get-ADUser -Filter { Name -eq $usu }

    if ($existeUsu -eq $null) {
        New-ADUser -Name $usu -SamAccountName $usu -DisplayName $usu -Path $pathUsuarios
        Write-Host "Usuario $usu creado en $pathUsuarios"
    } else {
        Write-Host "El usuario $usu ya había sido creado"
    }

    # Añadimos el usuario a su grupo global
    Add-ADGroupMember -Identity "$proy-$rolCorrecto" -Members $usu
    Write-Host "Usuario $usu añadido como miembro del grupo $proy-$rolCorrecto"

    # Añadir el grupo al que pertenece el usuario a una tabla hash en la que los usuarios son la clave y los grupos el valor
    if ($usu -notin $tabla_usuarios.Keys) {
        $tabla_usuarios[$usu] = @()
    }

    if ($rolCorrecto -eq "Responsables" -and $grCompleto -notin $tabla_usuarios[$usu]) {
        $tabla_usuarios[$usu] += $grCompleto
    }
    if ($rolCorrecto -eq "Investigadores" -and $grModificacion -notin $tabla_usuarios[$usu]) {
        $tabla_usuarios[$usu] += $grModificacion
    }
    if ($rolCorrecto -eq "Revisores" -and $grLectura -notin $tabla_usuarios[$usu]) {
        $tabla_usuarios[$usu] += $grLectura
    }
}

###################################################
################ Fin Funciones ####################
###################################################

#################
# Inicio Script #
#################

# Creacion de la carpeta 'C:\Proy-Temp\'
$carpetaProysRaiz = "C:\Proy-Temp\"

if (Test-Path $carpeta) {
    Remove-Item $carpeta -Recurse
    Write-Host "La carpeta $carpeta ya existe. Eliminandola..."
}
$carpeta = New-Item $carpeta -itemType "Directory"
Write-Host "Carpeta $carpeta creada"

# Comprobamos si existe la Unidad Organizativa Uni-Temp, si existe la eliminamos con todos sus objetos
# Si no existe la creamos con todas sus subUnidades Organizativas
$dn_unidad_padre = "dc=admon,dc=lab"
$nombre_unidadOrg = "Uni-Temp"

$existeUP = Get-ADOrganizationalUnit -Filter { Name -eq $nombre_unidadOrg }

if ($existeUP -ne $nul) {
    Remove-ADOrganizationalUnit $existeUP -Recursive -confirm:$false
    Write-Host "La unidad $existeUP ya existía en $dn_unidad_padre. Eliminándola ..."
}

# Crear UO Uni-Temp
$cUnidad = Crea_Unidad -NombreUnidad $nombre_unidadOrg  -ruta $dn_unidad_padre

# Crear UO Desarrollo
$nombre_unidadOrg = "Desarrollo"
$dn_unidad_padre  = "ou=Uni-Temp,dc=admon,dc=lab"
$cUnidad = Crea_Unidad -NombreUnidad $nombre_unidadOrg  -ruta $dn_unidad_padre

$dn_unidad_padre  = "ou=Desarrollo,ou=Uni-Temp,dc=admon,dc=lab"

# Crear UO Usuarios
$nombre_unidadOrg = "Usuarios"
$cUnidad = Crea_Unidad -NombreUnidad $nombre_unidadOrg  -ruta $dn_unidad_padre

# Crear UO Roles
$nombre_unidadOrg = "Roles"
$cUnidad = Crea_Unidad -NombreUnidad $nombre_unidadOrg  -ruta $dn_unidad_padre

# Crear UO Recursos
$nombre_unidadOrg = "Recursos"
$cUnidad = Crea_Unidad -NombreUnidad $nombre_unidadOrg  -ruta $dn_unidad_padre



##################################################################################################
# Segunda parte. Procesar fichero input.csv
##################################################################################################


$pathUsuarios = 'ou=Usuarios,ou=Desarrollo,ou=Uni-Pru,dc=admon,dc=lab' # Ruta para meter los usuarios creados
$pathRoles = 'ou=Roles,ou=Desarrollo,ou=Uni-Pru,dc=admon,dc=lab' # Ruta para meter los roles creados
$pathRecursos = 'ou=Recursos,ou=Desarrollo,ou=Uni-Pru,dc=admon,dc=lab' # Ruta para meter los grupos de dominio local creados

$tabla_usuarios = @{} # Tabla de usuarios

# Procesamos fichero input.csv
if (Test-Path ".\input.csv") {
    Import-Csv ".\input.csv" | ForEach-Object { Procesa $_ } # Proceso del fichero input.csv

    $usuarios = $tabla_usuarios.Keys
    Write-Host "" # Salto de línea
    Write-Host "INFORME FINAL: Pertenencia de usuarios a grupos de recursos"

    # Vamos a mostrar los usuarios ordenados y con sus grupos ordenados
    foreach ($u in ($usuarios | Sort-Object)) {
        $grupos = ($tabla_usuarios[$u] | Sort-Object) -join ", "
	    Write-Host "$u : $grupos"
    }
} else {
    Write-Host "No se encuentra el fichero input.csv"
}
