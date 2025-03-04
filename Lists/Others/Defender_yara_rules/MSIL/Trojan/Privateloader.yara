rule Trojan_MSIL_PrivateLoader_A_2147837874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PrivateLoader.A!MTB"
        threat_id = "2147837874"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 03 14 20 ?? 00 00 00 28 ?? 00 00 06 20 ?? 01 00 00 28 ?? 00 00 06 72 01 00 00 70 28 ?? 00 00 06 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 13 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PrivateLoader_B_2147849050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PrivateLoader.B!MTB"
        threat_id = "2147849050"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "creativelibamcreativelibsicreativelib.creativelibdcreativeliblcreativeliblcreativelib" wide //weight: 2
        $x_2_2 = "funfunAmfunfunsifunfunSfunfuncfunfunafunfunnBfunfunuffunfunfefunfunrfunfun" wide //weight: 2
        $x_2_3 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PrivateLoader_APL_2147892458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PrivateLoader.APL!MTB"
        threat_id = "2147892458"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 18 18 8c ?? 00 00 01 a2 25 19 18 8d 1f 00 00 01 25 17 18 8d 1f 00 00 01 25 16 11 06 a2 25 17 02 7b 1b 00 00 04 17 8d 1f 00 00 01 25 16 1c 8c ?? 00 00 01 a2 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PrivateLoader_SG_2147906259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PrivateLoader.SG!MTB"
        threat_id = "2147906259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 0a 2b 33 11 08 11 0a 8f 1a 00 00 01 25 71 1a 00 00 01 08 d2 61 d2 81 1a 00 00 01 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 08 8e 69 32 c5}  //weight: 1, accuracy: High
        $x_1_2 = "ScrubCrypt.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PrivateLoader_MBXQ_2147918551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PrivateLoader.MBXQ!MTB"
        threat_id = "2147918551"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bPkP1hYtjl.Fs5RDw4DygL" ascii //weight: 1
        $x_1_2 = {49 4d 4b 4a 58 45 00 41 4d 50 4b 43 51 4e 4e 45 41 58 56 42 50}  //weight: 1, accuracy: High
        $x_1_3 = "RJWxLgXCn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PrivateLoader_RDK_2147921744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PrivateLoader.RDK!MTB"
        threat_id = "2147921744"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 3d 00 00 0a 28 3e 00 00 0a 1a 8d 1e 00 00 01 25 16 28 3f 00 00 0a a2 25 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PrivateLoader_YOAA_2147922589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PrivateLoader.YOAA!MTB"
        threat_id = "2147922589"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 72 01 00 00 70 6f 1b 00 00 0a 28 ?? 00 00 0a 0b 73 1d 00 00 0a 0c 08 07 6f 1e 00 00 0a 00 08 18 6f 1f 00 00 0a 00 08 18 6f 20 00 00 0a 00 08 6f 21 00 00 0a 0d 09 06 16 06 8e 69 6f 22 00 00 0a 13 04 08 6f 23 00 00 0a 00 28 ?? 00 00 0a 11 04 6f 24 00 00 0a 13 05 2b 00 11 05 2a}  //weight: 3, accuracy: Low
        $x_2_2 = "Jta7pQclCEoU3erF7ka1uA==" wide //weight: 2
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PrivateLoader_NV_2147923481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PrivateLoader.NV!MTB"
        threat_id = "2147923481"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "QXNzZW1ibHlMb2FkZXJB" ascii //weight: 2
        $x_1_2 = "U3lzdGVtSW5mb0FB" ascii //weight: 1
        $x_1_3 = "UkRQSW5zdGFsbGVyQUFB" ascii //weight: 1
        $x_1_4 = "UkRQQ3JlYXRvcl9Qcm9jZXNzZWRCeUZvZHlB" ascii //weight: 1
        $x_1_5 = "0xb11a1" ascii //weight: 1
        $x_1_6 = "UploadValues" ascii //weight: 1
        $x_1_7 = "DownloadFileTaskAsync" ascii //weight: 1
        $x_1_8 = "IsPortOpen" ascii //weight: 1
        $x_1_9 = "SendCredentials" ascii //weight: 1
        $x_1_10 = "GenerateRandomPassword" ascii //weight: 1
        $x_1_11 = "AddUserToRemoteDesktopGroup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

