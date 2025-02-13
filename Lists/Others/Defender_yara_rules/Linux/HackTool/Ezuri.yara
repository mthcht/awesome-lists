rule HackTool_Linux_Ezuri_A_2147916717_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Ezuri.A"
        threat_id = "2147916717"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Ezuri"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "main.runFromMemory" ascii //weight: 2
        $x_2_2 = "main.aesDec" ascii //weight: 2
        $x_2_3 = "cipher.NewCFBDecrypter" ascii //weight: 2
        $x_2_4 = "XORKeyStream" ascii //weight: 2
        $x_2_5 = "main.main" ascii //weight: 2
        $x_2_6 = "syscall.Syscall" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

