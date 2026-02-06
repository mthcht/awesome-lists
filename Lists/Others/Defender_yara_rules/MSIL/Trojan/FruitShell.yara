rule Trojan_MSIL_FruitShell_GVA_2147962542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FruitShell.GVA!MTB"
        threat_id = "2147962542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FruitShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "$apple = $apple -replace 'x', '.'" ascii //weight: 1
        $x_1_2 = ".Write((pwd).Path + '> ')" ascii //weight: 1
        $x_1_3 = "New-Object System.Net.Sockets.TcpClient($" ascii //weight: 1
        $x_1_4 = "New-Object IO.StreamWriter($" ascii //weight: 1
        $x_1_5 = "New-Object IO.StreamReader($" ascii //weight: 1
        $x_1_6 = {49 6e 76 6f 6b 65 2d 45 78 70 72 65 73 73 69 6f 6e 20 24 [0-32] 20 7c 20 4f 75 74 2d 53 74 72 69 6e 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

