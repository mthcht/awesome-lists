rule Trojan_Win64_Nekark_EC_2147850518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Nekark.EC!MTB"
        threat_id = "2147850518"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {40 32 2c 02 41 88 2c 3c 48 83 c7 01 49 39 fd 0f 84 0e 01 00 00}  //weight: 4, accuracy: High
        $x_1_2 = "bjzcknpjq|zbznwhwdgaolyqxzkhpwdlbjjc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Nekark_NIT_2147928821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Nekark.NIT!MTB"
        threat_id = "2147928821"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 4b 28 c7 44 24 50 01 00 10 00 ff 15 6e cf 0d 00 31 d2 48 8b 4b 28 ff 15 a2 cf 0d 00 3d 02 01 00 00 75 93 48 8b 4b 28 4c 89 e2 ff 15 56 ce 0d 00 48 8d 05 b7 fb ff ff 4c 89 e2 48 8b 4b 28 48 89 84 24 18 01 00 00 ff 15 12 cf 0d 00 0f b6 43 40 48 8b 35 27 24 0b 00 83 63 44 fe 83 e0 f0 48 8b 16 83 c8 05 88 43 40 48 85 d2 0f 84 54 01 00 00 48 83 7a 18 00 0f 84 39 01 00 00 48 8b 42 18 f0 83 00 01 48 8b 4b 30 48 85 c9 74 06 ff 15 b4 ce 0d 00 4c 89 e9 e8 04 ab ff ff 48 8b 4b 28 ff 15 7a ce 0d 00 e9 0d ff ff ff}  //weight: 2, accuracy: High
        $x_1_2 = "And go touch some grass" ascii //weight: 1
        $x_1_3 = "Stop reversing the program" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Nekark_NN_2147940430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Nekark.NN!MTB"
        threat_id = "2147940430"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "in esecuzione come amministratore. Riavvio con privilegi elevati..." ascii //weight: 2
        $x_1_2 = "Inserisci il testo da analizzare" ascii //weight: 1
        $x_1_3 = "ramerson patrick solution fabric omebralesrtup beraitod" ascii //weight: 1
        $x_1_4 = "Nessun input ricevuto. Utilizzo del testo predefinito" ascii //weight: 1
        $x_1_5 = "opretorsa.pdb" ascii //weight: 1
        $x_1_6 = "Add-MpPreference -ExclusionPath" ascii //weight: 1
        $x_1_7 = "Invoke-WebRequest -Uri" ascii //weight: 1
        $x_1_8 = "Download del file 3 fallito" ascii //weight: 1
        $x_1_9 = "powershell -Command" ascii //weight: 1
        $x_1_10 = "Cartelle aggiunte alle esclusioni di Windows Defender" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

