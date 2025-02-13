rule TrojanSpy_MSIL_Omaneat_A_2147695700_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Omaneat.A"
        threat_id = "2147695700"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Omaneat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Host>(.+?)</Host>\\s+.+\\s+.+\\s+.+\\s+<User>(.+?)</User>\\s+<Pass>(.+?)</Pass>" wide //weight: 1
        $x_1_2 = "FUCKUP" wide //weight: 1
        $x_1_3 = "Installed Miner Successfully! Miner ID: " wide //weight: 1
        $x_1_4 = "Cannot Read Saved Keylog: " wide //weight: 1
        $x_1_5 = "*Started*BYT3S*" wide //weight: 1
        $x_1_6 = "=P4CK3T=" wide //weight: 1
        $x_1_7 = "NO|CRYPT" wide //weight: 1
        $x_1_8 = "G4ARD1AN" wide //weight: 1
        $x_1_9 = "*0*DECIDE*Queued*" wide //weight: 1
        $x_1_10 = "=Folder=N/A=" wide //weight: 1
        $x_1_11 = "DestroyPC" wide //weight: 1
        $x_1_12 = "Proactive Anti-Malware could not be enabled because this client does not use Luminosity's startup!" wide //weight: 1
        $x_1_13 = {2b 38 11 04 20 b0 57 b6 00 5c 18}  //weight: 1, accuracy: High
        $x_1_14 = {11 05 1a 5c 58 11 05 11 05 65 58 1f 1e 62 33 0d 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_MSIL_Omaneat_B_2147697422_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Omaneat.B"
        threat_id = "2147697422"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Omaneat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Host>(.+?)</Host>\\s+.+\\s+.+\\s+.+\\s+<User>(.+?)</User>\\s+<Pass>(.+?)</Pass>" ascii //weight: 1
        $x_1_2 = "FUCKUP" ascii //weight: 1
        $x_1_3 = "Installed Miner Successfully! Miner ID: " ascii //weight: 1
        $x_1_4 = "Cannot Read Saved Keylog: " ascii //weight: 1
        $x_1_5 = "*Started*BYT3S*" ascii //weight: 1
        $x_1_6 = "=P4CK3T=" ascii //weight: 1
        $x_1_7 = "NO|CRYPT" ascii //weight: 1
        $x_1_8 = "G4ARD1AN" ascii //weight: 1
        $x_1_9 = "*0*DECIDE*Queued*" ascii //weight: 1
        $x_1_10 = "=Folder=N/A=" ascii //weight: 1
        $x_1_11 = "DestroyPC" ascii //weight: 1
        $x_1_12 = "Proactive Anti-Malware could not be enabled because this client does not use Luminosity's startup!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_MSIL_Omaneat_C_2147706930_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Omaneat.C"
        threat_id = "2147706930"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Omaneat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Host>(.+?)</Host>\\s+.+\\s+.+\\s+.+\\s+<User>(.+?)</User>\\s+<Pass>(.+?)</Pass>" ascii //weight: 1
        $x_1_2 = "STOPDDOS" ascii //weight: 1
        $x_1_3 = "STARTCAM" ascii //weight: 1
        $x_1_4 = "LuminosityCryptoMiner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_MSIL_Omaneat_H_2147717382_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Omaneat.H!bit"
        threat_id = "2147717382"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Omaneat"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "|System.Resources.ResourceManager|Invoke" wide //weight: 1
        $x_1_2 = {03 50 06 03 50 06 91 02 7b ?? ?? ?? ?? 06 02 7b ?? ?? ?? ?? 8e 69 5d 91 61 28 ?? ?? ?? ?? 9c 06 17 58 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Omaneat_I_2147718890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Omaneat.I!bit"
        threat_id = "2147718890"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Omaneat"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = ":Zone.Identifier" wide //weight: 10
        $x_10_2 = "%ITSELFINJECTION%" wide //weight: 10
        $x_10_3 = {4e 00 74 00 53 00 65 00 74 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 54 00 68 00 72 00 65 00 61 00 64 00 [0-2] 4e 00 74 00 55 00 6e 00 6d 00 61 00 70 00 56 00 69 00 65 00 77 00 4f 00 66 00 53 00 65 00 63 00 74 00 69 00 6f 00 6e 00}  //weight: 10, accuracy: Low
        $x_1_4 = "snxhk.dll" wide //weight: 1
        $x_1_5 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

