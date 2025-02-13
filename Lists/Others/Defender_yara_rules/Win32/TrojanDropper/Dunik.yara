rule TrojanDropper_Win32_Dunik_2147745394_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dunik!MSR"
        threat_id = "2147745394"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dunik"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RunProgram=\"hidcon:O87414.bat\"" ascii //weight: 1
        $x_1_2 = "InstallPath=\"%APPDATA%\\Ofice\"" ascii //weight: 1
        $x_1_3 = ";SelfDelete=\"1\"" ascii //weight: 1
        $x_1_4 = "MSRC4Plugin_for_sc.dsm" ascii //weight: 1
        $x_1_5 = "Y3hghShFhYhNhGhm.ini" ascii //weight: 1
        $x_1_6 = "t5MCMWMjM6M4MRMC.png" ascii //weight: 1
        $x_1_7 = "Nhoioao2oiotoHor.png" ascii //weight: 1
        $x_1_8 = "rc4.key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanDropper_Win32_Dunik_AG_2147843062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dunik.AG!MSR"
        threat_id = "2147843062"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dunik"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\gusiti kijice\\daz wimakacovive53\\toluj68-p.pdb" ascii //weight: 10
        $x_2_2 = "SoftProd" ascii //weight: 2
        $x_2_3 = "SlayerPath" ascii //weight: 2
        $x_1_4 = "Nofimodupucisuc nubexewe latobacajicupi xasumevowaj wijohipi" ascii //weight: 1
        $x_1_5 = "GlobalReAlloc" ascii //weight: 1
        $x_1_6 = "ClientToScreen" ascii //weight: 1
        $x_1_7 = "CreateFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Dunik_AG_2147843062_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dunik.AG!MSR"
        threat_id = "2147843062"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dunik"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\batajahupudobu\\kemo31 camalixuhixa-hifap\\towov.pdb" ascii //weight: 10
        $x_1_2 = "Dixehun mohuhutosezasaf yeladuyorowil gepedoxasileteLKadip" ascii //weight: 1
        $x_1_3 = "Nofimodupucisuc nubexewe latobacajicupi xasumevowaj wijohipi" ascii //weight: 1
        $x_1_4 = "HeapReAlloc" ascii //weight: 1
        $x_1_5 = "ClientToScreen" ascii //weight: 1
        $x_1_6 = "CreateFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

