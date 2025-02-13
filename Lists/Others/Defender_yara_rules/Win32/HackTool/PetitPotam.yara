rule HackTool_Win32_PetitPotam_A_2147808757_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PetitPotam.A!MTB"
        threat_id = "2147808757"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PetitPotam"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 08 4b 4f 00 6a 64 8d ?? ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 83 c4 10 8b f4 8d ?? ?? ?? ?? ?? 50 6a 00 8b 0d 58 4a 4f 00 51 8d ?? ?? ?? ?? ?? 52 68 14 4b 4f 00 a1 54 ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 8d 45 f8 50 68 00 04 00 00 8b 4d 08 51 6a 00 68 00 13 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 08 b8 04 00 00 00 c1 e0 00 8b 4d 0c 8b 14 01 52 68 b8 4c 4f 00 6a 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_PetitPotam_B_2147809161_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PetitPotam.B!MTB"
        threat_id = "2147809161"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PetitPotam"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c681d488-d850-11d0-8c52-00c04fd90f7e" wide //weight: 1
        $x_1_2 = "EfsRpcOpenFileRaw" ascii //weight: 1
        $x_1_3 = "EfsRpcEncryptFileSrv" ascii //weight: 1
        $x_1_4 = "EfsRpcDecryptFileSrv" ascii //weight: 1
        $x_1_5 = "EfsRpcQueryUsersOnFile" ascii //weight: 1
        $x_1_6 = "EfsRpcQueryRecoveryAgents" ascii //weight: 1
        $x_1_7 = "EfsRpcRemoveUsersFromFile" ascii //weight: 1
        $x_1_8 = "EfsRpcAddUsersToFile" ascii //weight: 1
        $x_1_9 = "PetitPotam.exe" ascii //weight: 1
        $x_1_10 = "topotam" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

