rule Ransom_Win32_Nokonoko_PB_2147843258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nokonoko.PB!MTB"
        threat_id = "2147843258"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nokonoko"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 50 01 8d 40 ?? 0f b6 48 ?? c1 e2 08 03 d1 0f b6 48 ?? c1 e2 08 03 d1 0f b6 48 fa c1 e2 08 03 ca 89 4c 3d c0 89 4c 3d 80 83 c7 04 83 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b fe 83 e7 3f 8a 44 3d ?? 30 04 1e 46 3b 75 14 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nokonoko_ZA_2147843481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nokonoko.ZA"
        threat_id = "2147843481"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nokonoko"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {0f be 0e 8d 76 01 33 ?? c1 ?? ?? 0f b6 c9 33 ?? 8d 70 ?? ?? ?? 83 ?? 01 75 e6}  //weight: 10, accuracy: Low
        $x_1_3 = {fc 70 79 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nokonoko_ZB_2147843483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nokonoko.ZB"
        threat_id = "2147843483"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nokonoko"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba d0 03 5c 09 b9 30 59 aa 00 e8 bf 1d 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {ba e2 08 85 99 b9 30 59 aa 00 e8 8b 1d 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {ba 12 56 e9 cc b9 30 59 aa 00 e8 6d 1d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nokonoko_PAA_2147845704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nokonoko.PAA!MTB"
        threat_id = "2147845704"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nokonoko"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Couldn't create ransom note" ascii //weight: 1
        $x_1_2 = "Couldn't rename file" ascii //weight: 1
        $x_1_3 = "DELETE_SHADOW\\" ascii //weight: 1
        $x_1_4 = "delete shadow copies" ascii //weight: 1
        $x_1_5 = "Q:\\W:\\E:\\R:\\T:\\Y:\\U:\\I:\\O:\\P:\\A:\\S:\\D:\\F:\\G:\\H:\\J:\\K:\\L:\\Z:\\X:\\C:\\V:\\B:\\N:\\M:\\" ascii //weight: 1
        $x_1_6 = "/rustc/" ascii //weight: 1
        $x_1_7 = "ENCRYPT_NETWORK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nokonoko_PC_2147846865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nokonoko.PC!MTB"
        threat_id = "2147846865"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nokonoko"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "c2htb2tvc2htb2tv" ascii //weight: 1
        $x_1_2 = "bm9rb25va28=" ascii //weight: 1
        $x_1_3 = "REVMRVRFX1NIQURPVw==" ascii //weight: 1
        $x_1_4 = "RU5DUllQVF9ORVRXT1JL" ascii //weight: 1
        $x_10_5 = {8b d0 c1 ce 02 89 45 f8 c1 c2 05 03 55 80 8b c3 33 c6 81 c7 ?? ?? ?? ?? 23 45 fc 33 c3 81 c3 ?? ?? ?? ?? 03 c2 03 c7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nokonoko_PD_2147846912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nokonoko.PD!MTB"
        threat_id = "2147846912"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nokonoko"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4e 44 35 ?? ?? ?? ?? 01 46 5c a1 ?? ?? ?? ?? 8b 55 14 c1 ea 08 88 14 08 ff 46 44 8b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 55 14 88 14 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nokonoko_ZA_2147848938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nokonoko.ZA!MTB"
        threat_id = "2147848938"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nokonoko"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 8d 04 c0 03 c0 03 c0 8b d1 2b d0 8a 82 ?? ?? ?? ?? 32 81 ?? ?? ?? ?? 8b 54 24 ?? 88 04 11 41 3b 4c 24 ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nokonoko_AD_2147849105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nokonoko.AD!MTB"
        threat_id = "2147849105"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nokonoko"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "201"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {8b fa 8b c2 c1 c7 ?? c1 c0 ?? 33 f8 c1 ea ?? 33 fa 8b c6 c1 c8 ?? 8b d6 c1 c2 ?? 33 c2 c1 ee ?? 33 c6 05 ?? ?? ?? ?? 03 c7 03 43 ?? 03 43 ?? 03 c1 41 89 43 ?? 81 f9 ?? ?? ?? ?? 7c ba}  //weight: 100, accuracy: Low
        $x_100_3 = {8d 4d a8 03 ca 42 8a 04 19 32 01 88 04 31 3b d7 72 ee}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nokonoko_PYE_2147852561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nokonoko.PYE!MTB"
        threat_id = "2147852561"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nokonoko"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4d a8 03 ca 42 8a 04 19 32 01 88 04 31 3b d7}  //weight: 1, accuracy: High
        $x_1_2 = {33 ca 8b d1 8b c1 c1 e8 10 81 e2 00 00 ff 00 0b d0 8b c1 c1 e0 10 81 e1 00 ff 00 00 0b c1 c1 ea 08 0f b6 8f ?? ?? ?? ?? c1 e0 08 0b d0 0f b6 87}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

