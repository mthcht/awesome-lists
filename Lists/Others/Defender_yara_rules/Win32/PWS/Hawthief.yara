rule PWS_Win32_Hawthief_A_2147601466_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Hawthief.A"
        threat_id = "2147601466"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Hawthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Internet Explorer_Server" ascii //weight: 1
        $x_1_2 = "EmbeddedWB http://bsalsa." ascii //weight: 1
        $x_1_3 = "mensagem(ns)" ascii //weight: 1
        $x_1_4 = "http://by137w.bay137.mail." wide //weight: 1
        $x_1_5 = "contacttemp.html" ascii //weight: 1
        $x_1_6 = "dLogin_Mode_DiffUser" ascii //weight: 1
        $x_1_7 = "Tente novamente." ascii //weight: 1
        $x_1_8 = "/cgi-bin/compose?" ascii //weight: 1
        $x_1_9 = "MSNLOGOFF" ascii //weight: 1
        $x_1_10 = "SelectAllMessages" ascii //weight: 1
        $x_1_11 = "contacts.html" ascii //weight: 1
        $x_1_12 = ".aspx?FolderID=00000000" ascii //weight: 1
        $x_1_13 = "terra.com.br" ascii //weight: 1
        $x_1_14 = "Pegando os usu" ascii //weight: 1
        $x_1_15 = "Desconectando do hotmail" ascii //weight: 1
        $x_1_16 = {70 61 73 73 77 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

