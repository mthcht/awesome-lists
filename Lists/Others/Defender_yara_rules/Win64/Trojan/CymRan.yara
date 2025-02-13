rule Trojan_Win64_CymRan_ACN_2147895868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CymRan.ACN!MTB"
        threat_id = "2147895868"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CymRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 55 56 57 41 54 41 56 41 57 48 83 ec 30 33 ed 48 8b da 4c 8b f9 48 85 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CymRan_ACA_2147895882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CymRan.ACA!MTB"
        threat_id = "2147895882"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CymRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 44 24 40 48 83 b8 b8 00 00 00 ff 74 1f ff 15 84 89 03 00 83 f8 06 75 12 48 8b 44 24 40 48 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CymRan_B_2147897695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CymRan.B!MTB"
        threat_id = "2147897695"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CymRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\"+CymulateFileTargetName+\".tmp" ascii //weight: 2
        $x_2_2 = "new ActiveXObject(\"MSXml2.DOMDocument" ascii //weight: 2
        $x_2_3 = "new ActiveXObject(\"ADODB.Stream" ascii //weight: 2
        $x_2_4 = "objShell.Run(\"cmd.exe /c" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CymRan_C_2147900835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CymRan.C!MTB"
        threat_id = "2147900835"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CymRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\%ls\\IPC$ (username: %ls , password: %ls)" wide //weight: 2
        $x_2_2 = "Remote Host : %ls -> Service Name : %ls (username: %ls , password: %ls)" wide //weight: 2
        $x_2_3 = "log:DeleteService - %s" ascii //weight: 2
        $x_2_4 = "CymulateCredsStealNSpread" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CymRan_ACY_2147903341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CymRan.ACY!MTB"
        threat_id = "2147903341"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CymRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 c2 48 8d 0c 80 48 8d 05 67 99 03 00 48 8d 0c c8}  //weight: 1, accuracy: High
        $x_1_2 = {48 8d 0c 80 48 8d 05 f4 98 03 00 48 8d 0c c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

