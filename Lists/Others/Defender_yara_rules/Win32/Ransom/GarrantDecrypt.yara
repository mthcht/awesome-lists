rule Ransom_Win32_GarrantDecrypt_PA_2147762337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GarrantDecrypt.PA!MTB"
        threat_id = "2147762337"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GarrantDecrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "READ_ME.TXT" wide //weight: 1
        $x_1_2 = "delete shadows /all /quiet" wide //weight: 1
        $x_1_3 = "Your files are encrypted!" ascii //weight: 1
        $x_1_4 = "All your important data has been encrypted." ascii //weight: 1
        $x_1_5 = "Send 1 test image or text file squadhack@email.tg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GarrantDecrypt_PB_2147762338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GarrantDecrypt.PB!MTB"
        threat_id = "2147762338"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GarrantDecrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" wide //weight: 1
        $x_1_2 = "C:\\Windows\\sysnative" wide //weight: 1
        $x_1_3 = "delete shadows /all /quiet" wide //weight: 1
        $x_1_4 = "HELP_PC.EZDZ-REMOVE.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

