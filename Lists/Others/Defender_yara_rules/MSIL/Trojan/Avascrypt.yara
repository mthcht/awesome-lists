rule Trojan_MSIL_Avascrypt_RPY_2147836081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Avascrypt.RPY!MTB"
        threat_id = "2147836081"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Avascrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 00 38 00 35 00 2e 00 32 00 31 00 36 00 2e 00 37 00 31 00 2e 00 31 00 32 00 30 00 2f 00 [0-32] 2e 00 70 00 6e 00 67 00}  //weight: 10, accuracy: Low
        $x_10_2 = {38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 32 00 37 00 2f 00 [0-32] 2e 00 62 00 6d 00 70 00}  //weight: 10, accuracy: Low
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name" wide //weight: 1
        $x_1_5 = "WaitForExit" ascii //weight: 1
        $x_1_6 = "GZipStream" ascii //weight: 1
        $x_1_7 = "ToArray" ascii //weight: 1
        $x_1_8 = "WebRequest" ascii //weight: 1
        $x_1_9 = "GetType" ascii //weight: 1
        $x_1_10 = "InvokeMember" ascii //weight: 1
        $x_1_11 = "get_Length" ascii //weight: 1
        $x_1_12 = "Environment" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

