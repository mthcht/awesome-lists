rule Backdoor_Win64_Turla_B_2147691970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Turla.B!dha"
        threat_id = "2147691970"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 80 33 55 49 ff c3 48 83 e8 01 75 f3}  //weight: 1, accuracy: High
        $x_1_2 = {43 0f b6 04 01 49 ff c1 41 30 04 0a 49 83 f9 01 4c 0f 4d cb 49 ff c2 4d 3b d3 7c e4}  //weight: 1, accuracy: High
        $x_1_3 = "%I64uC%uK%uN0.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Turla_Z_2147731735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Turla.Z!dha"
        threat_id = "2147731735"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\pipe\\Winsock2\\CatalogChangeListener-FFFF-F" wide //weight: 1
        $x_1_2 = "InternetRelations::GetInetConnectToGazer" wide //weight: 1
        $x_1_3 = "PipeRelations::Pipe_NO_CONNECT_TO_GAYZER" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Turla_SA_2147760472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Turla.SA!MTB"
        threat_id = "2147760472"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 85 c0 75 ?? 8b cb 49 8b d1 4c 8b 05 ?? ?? ?? ?? 4d 2b c1 0f 1f 44 00 00 8b c1 25 ff 00 00 80 7d 09 ff c8 0d 00 ff ff ff ff c0 42 32 04 02 34 ?? 88 02 ff c1 48 ff c2 83 f9 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Turla_SK_2147760473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Turla.SK!MTB"
        threat_id = "2147760473"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b ca 81 e1 ff 00 00 80 7d ?? ff c9 81 c9 00 ff ff ff ff c1 43 ?? ?? ?? ?? 32 c1 34 ?? 41 88 00 ff c2 49 ff c0 83 fa ?? 72}  //weight: 5, accuracy: Low
        $x_2_2 = {48 c7 45 a0 ?? ?? ?? ?? 48 89 7d 98 66 89 7d 88 48 8d 55 e8 48 83 7d ?? ?? 48 0f 43 55 e8 45 33 c0 33 c9 ff 15 ?? ?? ?? ?? 48 c7 45 80 ?? ?? ?? ?? 48 89 7c 24 78 66 89 7c 24 68 49 83 c9 ff 45 33 c0 48 8d 55 e8 48 8d 4c 24 68 e8 ?? ?? ?? ?? 48 8d 4c 24 68 e8 ?? ?? ?? ?? 84 c0 75 ?? e8 ?? ?? ?? ?? 33 c9 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Turla_B_2147767376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Turla.B!MTB"
        threat_id = "2147767376"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "frontapp.dll" ascii //weight: 1
        $x_1_2 = "Clogperiod" ascii //weight: 1
        $x_1_3 = "\\\\.\\Global\\PIPE\\rpinforpc" ascii //weight: 1
        $x_1_4 = "net_password=" ascii //weight: 1
        $x_1_5 = "sacril.dll" ascii //weight: 1
        $x_1_6 = "Why the f*ck not" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Turla_A_2147767377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Turla.A!MTB"
        threat_id = "2147767377"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/javascript/view.php" ascii //weight: 10
        $x_10_2 = "no_server_hijack" ascii //weight: 10
        $x_10_3 = "5279C310-CA22-EAA1-FE49-C3A6A22AFC82" ascii //weight: 10
        $x_1_4 = "allow=*everyone" ascii //weight: 1
        $x_1_5 = "*.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Turla_DA_2147767380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Turla.DA!MTB"
        threat_id = "2147767380"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Why the f*ck not???" ascii //weight: 1
        $x_1_2 = "Alerter" ascii //weight: 1
        $x_1_3 = "sacril.dll" ascii //weight: 1
        $x_1_4 = "estdlawf.fes" ascii //weight: 1
        $x_1_5 = "If the service is stopped, programs that use administrative alerts will not receive them." ascii //weight: 1
        $x_1_6 = "If this service is disabled, any services that explicitly depend on it will fail to start." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win64_Turla_CD_2147951950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Turla.CD!MTB"
        threat_id = "2147951950"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 44 14 40 00 4c 8d 15 ?? ?? ?? ?? 80 7c 24 40 00 4c 8d 4c 24 40 74 3e 41 0f b6 02 84 c0 74 36 45 0f b6 01 41 8d 48 20 44 0f b6 d9 41 8d 50 bf 80 fa 19 8d 48 bf 45 0f 47 d8 80 f9 19 77}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

