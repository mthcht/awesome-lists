rule Trojan_O97M_AmsiTamper_2147735494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/AmsiTamper"
        threat_id = "2147735494"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AmsiTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "\"HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable\"" ascii //weight: 5
        $x_5_2 = "GetObject(\"new:72C24DD5-D70A-438B-8A42-98424B88AFB8\")" ascii //weight: 5
        $x_1_3 = ".RegWrite regpath, \"0\", \"REG_DWORD\"" ascii //weight: 1
        $x_1_4 = "CreateObject(\"Microsoft.XMLDOM\")" ascii //weight: 1
        $x_1_5 = ".async = False" ascii //weight: 1
        $x_1_6 = {2e 4c 6f 61 64 20 22 68 74 74 70 3a 2f 2f [0-96] 2f [0-16] 2e 78 73 6c 22}  //weight: 1, accuracy: Low
        $x_1_7 = ".transformNode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

