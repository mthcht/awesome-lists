rule Trojan_Win64_ReflectiveLoader_EM_2147850298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReflectiveLoader.EM!MTB"
        threat_id = "2147850298"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReflectiveLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4c 8d 3c 3a 49 83 c7 28 48 89 d6 48 01 fe 4c 89 7c 24 78 89 9c 24 80 00 00 00 48 89 4c 24 58 48 8d 04 31 48 83 c0 28 48 89 44 24 50 48 89 84 24 88 00 00 00 44 89 b4 24 90 00 00 00 48 8d 9c 24 98 00 00 00 48 c7 03 00 00 00 00 48 89 5c 24 20}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ReflectiveLoader_RDA_2147914871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReflectiveLoader.RDA!MTB"
        threat_id = "2147914871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReflectiveLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "reflective_dll.x64.dll" ascii //weight: 2
        $x_1_2 = "Failed to get the DLL file size" ascii //weight: 1
        $x_1_3 = "[+] Injected the '%s' DLL into process %d." ascii //weight: 1
        $x_1_4 = "Failed to inject the DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ReflectiveLoader_OFA_2147947239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReflectiveLoader.OFA"
        threat_id = "2147947239"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReflectiveLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b bc 4a 6a}  //weight: 1, accuracy: High
        $x_1_2 = {5d 68 fa 3c}  //weight: 1, accuracy: High
        $x_1_3 = {8e 4e 0e ec}  //weight: 1, accuracy: High
        $x_1_4 = {aa fc 0d 7c}  //weight: 1, accuracy: High
        $x_1_5 = {54 ca af 91}  //weight: 1, accuracy: High
        $x_1_6 = {b8 0a 4c 53}  //weight: 1, accuracy: High
        $x_10_7 = "ReflectiveLoader" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

