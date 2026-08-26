rule Trojan_Win64_DllSideLoad_GVF_2147975994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllSideLoad.GVF!MTB"
        threat_id = "2147975994"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 85 38 bc ff ff 40 89 85 38 bc ff ff 0f b7 85 68 bd ff ff 39 85 38 bc ff ff 7d 3b 8b 85 38 bc ff ff 25 7f 00 00 80 79 05 48 83 c8 80 40 0f be 84 05 1c 9c ff ff 8b 8d 30 b7 ff ff 03 8d 38 bc ff ff 0f be 09 33 c8 8b 85 30 b7 ff ff 03 85 38 bc ff ff 88 08 eb a9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllSideLoad_ARA_2147976247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllSideLoad.ARA!MTB"
        threat_id = "2147976247"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b d7 c1 e2 0b 33 d7 8b fd 41 8b ee 45 8b f7 45 8b fe 41 c1 ef 13 45 33 fe 44 33 fa c1 ea 08 44 33 fa 41 8b d7 c1 ea 10 41 33 d7 45 8b c7 41 c1 e8 18 41 33 d0 0f b6 d2 44 8b c1 46 0f b6 44 03 10 44 33 c2 45 0f b6 c0 44 8b d1 46 88 44 10 10 03 fa ff c1 3b f1 7f a8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllSideLoad_GVG_2147976781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllSideLoad.GVG!MTB"
        threat_id = "2147976781"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "colorcpl.exe" ascii //weight: 1
        $x_1_2 = "Allocating buffer failed" ascii //weight: 1
        $x_1_3 = "Running the shellcode" ascii //weight: 1
        $x_1_4 = "Running again to unload the DLL" ascii //weight: 1
        $x_1_5 = "Load status" ascii //weight: 1
        $x_1_6 = "The shellcode finished with a return value" ascii //weight: 1
        $x_1_7 = "Creating a new thread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllSideLoad_GVH_2147977032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllSideLoad.GVH!MTB"
        threat_id = "2147977032"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hooked NTDLL .TEXT Section VA" ascii //weight: 1
        $x_1_2 = "NtOpenFile syscall number" ascii //weight: 1
        $x_1_3 = "NtOpenSection syscall number" ascii //weight: 1
        $x_1_4 = "NtCreateSection syscall number" ascii //weight: 1
        $x_1_5 = "Hooked NTDLL Base Address" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

