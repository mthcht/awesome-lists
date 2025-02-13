rule Trojan_Win32_FakeFilecoder_PA_2147749617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeFilecoder.PA!MTB"
        threat_id = "2147749617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeFilecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Strawberry Fields Crypto Locker" ascii //weight: 1
        $x_1_2 = "Your important files were encrypted on this computer" ascii //weight: 1
        $x_1_3 = {54 6f 20 72 65 74 72 69 65 76 65 20 74 68 65 20 70 72 69 76 61 74 65 20 6b 65 79 2e 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 70 61 79 20 [0-4] 20 62 69 74 63 6f 69 6e 73 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeFilecoder_GJO_2147848985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeFilecoder.GJO!MTB"
        threat_id = "2147848985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeFilecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "THIS RANSOMWARE HAS NOW INFILITRATED YOUR ENTIRE NETWORK" ascii //weight: 1
        $x_1_2 = "BOTH YOUR FILES AND BACKUPS ARE NOW ENCRYPTED" ascii //weight: 1
        $x_1_3 = "WE HAVE STOLEN ALL OF YOUR DATA AND NETWORK CREDENTIELS" ascii //weight: 1
        $x_1_4 = "PAY THE RANSOM IN ORDER FOR US TO CONSIDER GIVING YOU THE KEY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

