rule Ransom_Win32_DefrayCrypt_A_2147723188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DefrayCrypt.A"
        threat_id = "2147723188"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DefrayCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "e=%d&s=%d&f=%d&t=%d&h=%ls&w=%d&r=%ls" ascii //weight: 3
        $x_2_2 = "(\\\\[a-zA-Z0-9_ ]+|[a-zA-Z]:)(((\\\\.+?(\\\\|))+(?=[<>\":\\/|?*\\n\\r\\t]))|((\\\\.+(\\\\|))+))" ascii //weight: 2
        $x_2_3 = "kinaesthetic-electr.000webhostapp.com" ascii //weight: 2
        $x_2_4 = "pe\\kiket" ascii //weight: 2
        $x_1_5 = "path=\".+\"" ascii //weight: 1
        $x_1_6 = "uri=\".+\"" ascii //weight: 1
        $x_1_7 = "<include>.+</include>" ascii //weight: 1
        $x_1_8 = {00 69 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 5c 46 49 4c 45 53 2e 54 58 54 00}  //weight: 1, accuracy: High
        $x_1_10 = "Encryption is very sophisticated and without paying a ransom you won't get your files back." ascii //weight: 1
        $x_1_11 = "BM-2cVPKqFb5ZRaMuYdryqxsMNxFMudibvnY6" ascii //weight: 1
        $x_1_12 = "glushkov@protonmail.ch" ascii //weight: 1
        $x_1_13 = "glushkov@tutanota.de" ascii //weight: 1
        $x_1_14 = "igor.glushkov.83@mail.ru" ascii //weight: 1
        $x_2_15 = {ff 5c 75 36 8d 45 f4 33 ff 50 ff 15 ?? ?? ?? ?? 2b c7 74 1e 83 e8 01 74 19 83 e8 01 74 14 83 e8 01 74 0f 83 e8 01 74 0a 83 e8 01 74 05 83 e8 01 75 08 8d 4d f4 e8 ?? ?? ff ff 46 3b f3 7c a2}  //weight: 2, accuracy: Low
        $x_2_16 = {75 07 bf a8 fd ff ff eb 17 53 8d 45 f8 50 57 ff 75 08 56 ff 15}  //weight: 2, accuracy: High
        $x_1_17 = {85 c0 74 03 89 46 08 8b 16 8b ce 6a 01 ff 12 57 ff 15}  //weight: 1, accuracy: High
        $x_2_18 = {be 40 01 00 00 39 b5 ?? ?? 00 00 7c ?? 8d 45 ?? 50 56 8b c8 e8 ?? ?? 00 00 ff 75 ?? 8b 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_DefrayCrypt_A_2147723189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DefrayCrypt.A!!DefrayCrypt.gen!A"
        threat_id = "2147723189"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DefrayCrypt"
        severity = "Critical"
        info = "DefrayCrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "e=%d&s=%d&f=%d&t=%d&h=%ls&w=%d&r=%ls" ascii //weight: 3
        $x_2_2 = "(\\\\[a-zA-Z0-9_ ]+|[a-zA-Z]:)(((\\\\.+?(\\\\|))+(?=[<>\":\\/|?*\\n\\r\\t]))|((\\\\.+(\\\\|))+))" ascii //weight: 2
        $x_2_3 = "kinaesthetic-electr.000webhostapp.com" ascii //weight: 2
        $x_2_4 = "pe\\kiket" ascii //weight: 2
        $x_1_5 = "path=\".+\"" ascii //weight: 1
        $x_1_6 = "uri=\".+\"" ascii //weight: 1
        $x_1_7 = "<include>.+</include>" ascii //weight: 1
        $x_1_8 = {00 69 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 5c 46 49 4c 45 53 2e 54 58 54 00}  //weight: 1, accuracy: High
        $x_1_10 = "Encryption is very sophisticated and without paying a ransom you won't get your files back." ascii //weight: 1
        $x_1_11 = "BM-2cVPKqFb5ZRaMuYdryqxsMNxFMudibvnY6" ascii //weight: 1
        $x_1_12 = "glushkov@protonmail.ch" ascii //weight: 1
        $x_1_13 = "glushkov@tutanota.de" ascii //weight: 1
        $x_1_14 = "igor.glushkov.83@mail.ru" ascii //weight: 1
        $x_2_15 = {ff 5c 75 36 8d 45 f4 33 ff 50 ff 15 ?? ?? ?? ?? 2b c7 74 1e 83 e8 01 74 19 83 e8 01 74 14 83 e8 01 74 0f 83 e8 01 74 0a 83 e8 01 74 05 83 e8 01 75 08 8d 4d f4 e8 ?? ?? ff ff 46 3b f3 7c a2}  //weight: 2, accuracy: Low
        $x_2_16 = {75 07 bf a8 fd ff ff eb 17 53 8d 45 f8 50 57 ff 75 08 56 ff 15}  //weight: 2, accuracy: High
        $x_1_17 = {85 c0 74 03 89 46 08 8b 16 8b ce 6a 01 ff 12 57 ff 15}  //weight: 1, accuracy: High
        $x_2_18 = {be 40 01 00 00 39 b5 ?? ?? 00 00 7c ?? 8d 45 ?? 50 56 8b c8 e8 ?? ?? 00 00 ff 75 ?? 8b 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

