rule Trojan_MSIL_ExtenBro_A_2147696431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ExtenBro.A"
        threat_id = "2147696431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ExtenBro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\schtasks.exe /create /f /tn" wide //weight: 1
        $x_1_2 = "http://walkonmoonnn.info/" wide //weight: 1
        $x_1_3 = "http://flytome.info/" wide //weight: 1
        $x_1_4 = "/update6.txt" wide //weight: 1
        $x_1_5 = "\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar\\Google Chrome.lnk" wide //weight: 1
        $x_1_6 = "REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f /v updaterv" wide //weight: 1
        $x_1_7 = "k=36sayiiii" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

