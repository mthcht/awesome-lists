rule Trojan_MSIL_Perseus_DHE_2147742459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.DHE!MTB"
        threat_id = "2147742459"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 11 04 6f ?? ?? ?? ?? 0d ?? 09 28 ?? ?? ?? ?? ?? da 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? ?? 11 04 17 d6 13 04 11 04 11 06}  //weight: 1, accuracy: Low
        $x_1_2 = "EntryPoint" wide //weight: 1
        $x_1_3 = "Invoke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Perseus_AKR_2147753291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.AKR!MTB"
        threat_id = "2147753291"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CC80C4A1144C17E26B48CF5211459F54E38FAC8A50CB9EAEDE067F836222C2D9" ascii //weight: 2
        $x_2_2 = "1DB2A1F9902B35F8F880EF1692CE9947A193D5A698D8F568BDA721658ED4C58B" ascii //weight: 2
        $x_1_3 = "STAThreadAttribute" ascii //weight: 1
        $x_1_4 = "CompilerGeneratedAttribute" ascii //weight: 1
        $x_1_5 = "GuidAttribute" ascii //weight: 1
        $x_1_6 = "GeneratedCodeAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_10 = "EditorBrowsableAttribute" ascii //weight: 1
        $x_1_11 = "ComVisibleAttribute" ascii //weight: 1
        $x_1_12 = "AssemblyTitleAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Perseus_A_2147763108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.A!MTB"
        threat_id = "2147763108"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "cG93ZXJzaGVsbA==" wide //weight: 3
        $x_10_2 = "LWVwIGJ5cGFzcyAtdyBoaWRkZW4gLWZpbGUgYzpcdXNlcnNccHVibGljXFJFR19USU1FLnBzMQ==" wide //weight: 10
        $x_3_3 = "XBwbGljYXRpb24gbXVzdCBi" wide //weight: 3
        $x_1_4 = ".pdf" ascii //weight: 1
        $x_1_5 = "frombase64string" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Perseus_XA_2147768475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.XA!MTB"
        threat_id = "2147768475"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "63"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GZipStream" ascii //weight: 1
        $x_1_2 = "DecompressGZip" ascii //weight: 1
        $x_1_3 = "ConfusedByAttribute" ascii //weight: 1
        $x_20_4 = {63 6f 73 74 75 72 61 2e [0-8] 2e 64 6c 6c 2e 64 6c 6c 2e 7a 69 70}  //weight: 20, accuracy: Low
        $x_20_5 = {63 6f 73 74 75 72 61 2e [0-8] 2e 64 6c 6c 2e 70 64 62 2e 7a 69 70}  //weight: 20, accuracy: Low
        $x_20_6 = "Waves.Resources.resources" ascii //weight: 20
        $x_1_7 = "toto" ascii //weight: 1
        $x_1_8 = "Waves.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Perseus_XB_2147768476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.XB!MTB"
        threat_id = "2147768476"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "costura.http.inf.dll.zip" ascii //weight: 1
        $x_1_2 = "costura.http.inf.pdb.zip" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" wide //weight: 1
        $x_1_4 = "bytesToDecompress" ascii //weight: 1
        $x_1_5 = "DecompressGZip" ascii //weight: 1
        $x_1_6 = {53 65 74 74 69 6e 67 73 [0-15] 74 74 00 42 79 74 65 00 75 6b 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_MSIL_Perseus_RW_2147779787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.RW!MTB"
        threat_id = "2147779787"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_Username" ascii //weight: 1
        $x_1_2 = "get_Password" ascii //weight: 1
        $x_1_3 = "set_Proxy" ascii //weight: 1
        $x_5_4 = "$54a9a1d1-1341-4fce-a8ff-a91c44a8c82e" ascii //weight: 5
        $x_10_5 = "User is not logged in, possible breach detected!" wide //weight: 10
        $x_10_6 = "Possible malicious activity detected!" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Perseus_ABM_2147789167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.ABM!MTB"
        threat_id = "2147789167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "myself.dll" ascii //weight: 3
        $x_3_2 = "Beef.dll" ascii //weight: 3
        $x_3_3 = "rOnAlDo" ascii //weight: 3
        $x_3_4 = "ContainsKey" ascii //weight: 3
        $x_3_5 = "managament.inf" ascii //weight: 3
        $x_3_6 = "costura.managament.inf.dll.zip" ascii //weight: 3
        $x_3_7 = "ProcessedByFody" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Perseus_OEH_2147824716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.OEH!MTB"
        threat_id = "2147824716"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 08 95 9e 11 04 08 09 9e 11 05 11 08 02 11 08 91 11 04 11 04 07 95 11 04 08 95 58 20 ff 00 00 00 5f 95 61 28 ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Perseus_NE_2147833498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.NE!MTB"
        threat_id = "2147833498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "b11619ca4d66ceeb59c7c5fb8e8e738d" ascii //weight: 5
        $x_5_2 = "Cal Stereo" ascii //weight: 5
        $x_5_3 = "get__6d87295" ascii //weight: 5
        $x_5_4 = "Administrative project coordinator" ascii //weight: 5
        $x_5_5 = "Motor Vehicle Manufacturing" ascii //weight: 5
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Perseus_GCE_2147838180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.GCE!MTB"
        threat_id = "2147838180"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "R3dBQUNnQUFLZ0FBQUJNd0FnQ" wide //weight: 1
        $x_1_2 = "BQUFLZmdrQUFBUW9Gd0FBQ2d2ZUl" wide //weight: 1
        $x_1_3 = "Kalari.exe" ascii //weight: 1
        $x_1_4 = "UrlTokenDecode" ascii //weight: 1
        $x_1_5 = "useisus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MSIL_Perseus_BAA_2147840314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.BAA!MTB"
        threat_id = "2147840314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 08 11 04 8f ?? 00 00 01 72 87 0e 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 26 11 04 17 58 13 04 11 04 08 8e 69 32 da}  //weight: 2, accuracy: Low
        $x_1_2 = "jid1-3XsqxCV3IYKObw@jetpack.xpi" wide //weight: 1
        $x_1_3 = "static/Cin.exe" wide //weight: 1
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
        $x_1_7 = "Software\\ICNS\\BT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Perseus_PSPL_2147848881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.PSPL!MTB"
        threat_id = "2147848881"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 02 0a 28 26 ?? ?? ?? 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 28 ?? ?? ?? 0a 0c 08 28 ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 04 06 09 11 04 28 ?? ?? ?? 06 13 05 11 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Perseus_APR_2147850289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.APR!MTB"
        threat_id = "2147850289"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 08 16 72 ?? ?? ?? 70 a2 00 08 17 7e 07 00 00 04 a2 00 08 18 72 ?? ?? ?? 70 a2 00 08 19 28 ?? ?? ?? 0a a2 00 08 1a 72}  //weight: 2, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
        $x_1_3 = "CMDrShellSTUB" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Perseus_PSSS_2147851256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.PSSS!MTB"
        threat_id = "2147851256"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {17 28 2f 00 00 06 13 08 11 08 02 1a 02 8e 69 1a 59 6f 72 00 00 0a 28 41 00 00 06 0c de 2d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Perseus_GNP_2147851567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.GNP!MTB"
        threat_id = "2147851567"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 1f 0b 28 ?? ?? ?? 06 0b 1f 38 28 ?? ?? ?? 06 0c 02 1c 8d ?? ?? ?? ?? 25 16 72 ?? ?? ?? ?? a2 25 17 06 a2 25 18 72 ?? ?? ?? ?? a2 25 19 07 a2 25 1a 72 ?? ?? ?? ?? a2 25 1b 08 a2}  //weight: 10, accuracy: Low
        $x_1_2 = "PXwY7mBDma5hf2MkFX95wYyDBc8WBbDfYY5GWgbTgRM8Hq4Yc3" ascii //weight: 1
        $x_1_3 = "zFS3X48n9q35dZaE55D4yy7Z7S23NkPRbhB5GfhDt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Perseus_KA_2147890154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.KA!MTB"
        threat_id = "2147890154"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 08 02 07 17 28 ?? 00 00 0a 28 ?? 00 00 0a 61 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 58 b5 0b 07 11 04 31 d6}  //weight: 10, accuracy: Low
        $x_10_2 = {11 07 6e 17 6a d6 20 ?? 00 00 00 6a 5f b8 13 07 11 06 09 11 07 84 95 d7 6e 20 ?? 00 00 00 6a 5f b8 13 06 09 11 07 84 95 0a 09 11 07 84 09 11 06 84 95 9e 09 11 06 84 06 9e 11 05 07 02 07 91 09 09 11 07 84 95 09 11 06 84 95 d7 6e 20 ?? 00 00 00 6a 5f b7 95 61 86 9c 07 17 d6 0b 07 11 0a 31 9f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Perseus_AP_2147891443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.AP!MTB"
        threat_id = "2147891443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 16 0d 2b 22 08 09 9a 13 04 11 04 6f 94 00 00 0a 2c 10 11 04 6f 95 00 00 0a 6f 2c 00 00 0a 10 01 2b 0a 09 17 58 0d 09 08 8e 69 32 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Perseus_KAA_2147891725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.KAA!MTB"
        threat_id = "2147891725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 11 05 02 11 05 91 08 61 06 11 04 91 61 b4 9c 1e}  //weight: 5, accuracy: High
        $x_5_2 = {b7 17 da 91 1f 70 61 0c 1f 0a 2b 6a 07}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Perseus_PTAK_2147894738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.PTAK!MTB"
        threat_id = "2147894738"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 97 00 00 70 72 9d 00 00 70 6f 13 00 00 0a 72 a1 00 00 70 72 a7 00 00 70 6f 13 00 00 0a 72 ab 00 00 70 72 b1 00 00 70 6f 13 00 00 0a 28 ?? 00 00 0a 13 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Perseus_MA_2147901836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.MA!MTB"
        threat_id = "2147901836"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://hwid31.000webhostapp.com" wide //weight: 1
        $x_1_2 = "IsKeyDown" ascii //weight: 1
        $x_1_3 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_4 = "KeyPress" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
        $x_1_6 = "Form1_Load" ascii //weight: 1
        $x_1_7 = "IDAPro" wide //weight: 1
        $x_1_8 = "Kill" ascii //weight: 1
        $x_1_9 = "IDADemo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Perseus_NITA_2147945267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.NITA!MTB"
        threat_id = "2147945267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 11 01 00 70 28 ?? 00 00 0a 74 28 00 00 01 13 09 11 09 6f ?? 00 00 0a 74 29 00 00 01 13 0a 11 0a 6f ?? 00 00 0a 73 2f 00 00 0a 6f ?? 00 00 0a 13 0b 73 31 00 00 0a 13 0c 11 0c 11 0b 6f ?? 00 00 0a 00 11 0c 6f ?? 00 00 0a 6f ?? 00 00 0a 16 6f ?? 00 00 0a 6f ?? 00 00 0a 13 0d 28 ?? 00 00 0a 72 05 01 00 70 11 05 11 06 72 fd 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0e 11 0e 17 18 73 37 00 00 0a 13 1b}  //weight: 3, accuracy: Low
        $x_2_2 = {72 c0 01 00 70 28 ?? 00 00 0a 74 28 00 00 01 13 0f 11 0f 6f ?? 00 00 0a 74 29 00 00 01 13 10 11 10 6f ?? 00 00 0a 73 2f 00 00 0a 6f ?? 00 00 0a 13 11 73 31 00 00 0a 13 12 11 12 11 11 6f ?? 00 00 0a 00 11 12 6f ?? 00 00 0a 6f ?? 00 00 0a 16 6f ?? 00 00 0a 6f ?? 00 00 0a 13 13 02 7b 0b 00 00 04 1f 1e 6f ?? 00 00 0a 00 02 7b 08 00 00 04 72 6f 02 00 70 6f ?? 00 00 0a 00 28 ?? 00 00 0a 72 9d 02 00 70 11 05 11 06 72 fd 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 13 14 11 14 17 18 73 37 00 00 0a 13 1d 00 11 13 28 ?? 00 00 0a 13 1e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Perseus_SLDZ_2147951562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Perseus.SLDZ!MTB"
        threat_id = "2147951562"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1a 59 28 13 00 00 0a 13 05 11 05 8d 11 00 00 01 13 06 08 08 8e 69 18 59 1a 59 11 05 59 11 06 16 11 05 28 14 00 00 0a 00 11 06 28 01 00 00 2b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

