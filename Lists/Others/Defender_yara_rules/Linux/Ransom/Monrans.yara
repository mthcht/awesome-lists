rule Ransom_Linux_Monrans_A_2147953704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Monrans.A!MTB"
        threat_id = "2147953704"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Monrans"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.wipeSensitiveData" ascii //weight: 1
        $x_1_2 = "main.elevatePrivileges" ascii //weight: 1
        $x_1_3 = "main.disableSecurity" ascii //weight: 1
        $x_1_4 = "main.encryptShadowCopies" ascii //weight: 1
        $x_1_5 = "main.killProcessesUsingFile" ascii //weight: 1
        $x_1_6 = "main.reportEncryptedFiles" ascii //weight: 1
        $x_1_7 = "main.setWallpaper" ascii //weight: 1
        $x_1_8 = "/root/monkeyrans/monekey.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

