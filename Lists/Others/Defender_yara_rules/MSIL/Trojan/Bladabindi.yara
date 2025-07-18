rule Trojan_MSIL_Bladabindi_PA_2147744898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PA!MTB"
        threat_id = "2147744898"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "EntryPoint" wide //weight: 1
        $x_1_2 = "Invoke" wide //weight: 1
        $x_10_3 = {70 18 18 28 ?? 00 00 06 6f ?? 00 00 0a ?? ?? 14 72 ?? 00 00 70 14 14 14 14 28 ?? 00 00 0a 14 72 ?? 00 00 70 18 8d 01 00 00 01 [0-4] 16 16 8c ?? 00 00 01 a2 [0-2] 14 14 14 28 ?? 00 00 0a [0-2] 2a a0 00 28 ?? 00 00 06 ?? 28 ?? 00 00 0a 06 [0-2] 28 ?? 00 00 0a 28 ?? 00 00 0a}  //weight: 10, accuracy: Low
        $x_10_4 = {0a 0b 06 6f ?? 00 00 0a [0-2] 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a [0-2] 08 04 6f ?? 00 00 0a [0-2] 08 05 6f ?? 00 00 0a [0-2] 08 6f ?? 00 00 0a [0-2] 02 16 02 8e 69 6f ?? 00 00 0a [0-2] 0d 08 6f ?? 00 00 0a [0-2] 09 13 04 11 04 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_A_2147746000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.A!MTB"
        threat_id = "2147746000"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {e0 a4 96 e0 a4 a6 e0 a4 9a e0 a4 8b e0 a4 94 e0 a4 8f e0 a4 8f e0 a4 aa e0 a4 9a e0 a4 b7 e0 a4 a6 e0 a4 8f e0 a4 96 e0 a4 98 e0 a4 87 e0 a4 8f e0 a4 af e0 a4 a1 e0 a4 87 e0 a4 a8 e0 a4 aa e0 a4 ac e0 a4 ae e0 a4 9f e0 a4 b7 e0 a4 ad e0 a4 97 e0 a4 a3 e0 a4 a8 e0 a4 af 2e 65 78 65}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_A_2147746000_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.A!MTB"
        threat_id = "2147746000"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System Exporer.pdb" ascii //weight: 1
        $x_1_2 = "$696e2d30-a1fa-4815-8071-75788336b3a3" ascii //weight: 1
        $x_1_3 = "U3lzdGVtIEV4cG9yZXIk" ascii //weight: 1
        $x_1_4 = "Pdfffdwwfdwdwffddffwwfd" ascii //weight: 1
        $x_1_5 = ":processsshackerrrrrr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_A_2147746000_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.A!MTB"
        threat_id = "2147746000"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Firwmare\\anan.txt" wide //weight: 1
        $x_1_2 = "Firwmare\\csapp3.exe" wide //weight: 1
        $x_1_3 = "Source\\Repos\\deploy\\deploy\\obj\\Debug\\deploy.pdb" ascii //weight: 1
        $x_1_4 = "Windows USB Servisi" ascii //weight: 1
        $x_1_5 = "$18665594-f6e4-4ad8-a531-9d0a00520025" ascii //weight: 1
        $x_1_6 = "Bu Disk" wide //weight: 1
        $x_1_7 = "USBService.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AG_2147754169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AG!MTB"
        threat_id = "2147754169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 02 11 05 91 [0-16] 91 61 b4 9c [0-16] 00 00 04 6f [0-16] 0a 17 da fe 01 13 07 11 07 2c 04 16 [0-21] 00 11 05 17 d6 13 05 11 05 11 06 13 08 11 08 31 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {08 11 05 02 11 05 91 07 61 06 09 91 61 b4 9c 09 7e 72 01 00 04 6f 6a 00 00 0a 17 da 33 04 16 0d 2b 04 09 17 d6 0d 11 05 17 d6 13 05 11 05 11 04 31 ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Bladabindi_SBR_2147755683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SBR!MSR"
        threat_id = "2147755683"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 cf 00 00 70 7e 08 00 00 04 6f ?? 00 00 0a 72 13 01 00 70 28 ?? 00 00 0a 16 16 15 28 ?? 00 00 0a 26 de 03}  //weight: 1, accuracy: Low
        $x_1_2 = {11 05 12 06 28 ?? 00 00 06 13 07 11 07 28 ?? 00 00 06 28 ?? 00 00 0a 13 08 02 09 07 06 1b 16 11 08 28 ?? 00 00 06 26 06 6f ?? 00 00 0a 0c 08 13 09 de 10}  //weight: 1, accuracy: Low
        $x_1_3 = "TllBTiBDQVQ=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SBR_2147755683_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SBR!MSR"
        threat_id = "2147755683"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "crypter black cat semi fud = usar esse = final\\software.pdb" ascii //weight: 1
        $x_1_2 = "Software.Resources.resources" ascii //weight: 1
        $x_1_3 = "#Bw.#Th.resources" ascii //weight: 1
        $x_1_4 = "Cryptography.RijndaelManaged" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SBR_2147755683_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SBR!MSR"
        threat_id = "2147755683"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://45.138.172.158" wide //weight: 5
        $x_1_2 = "Lightshotinstaller.Properties.Resources" wide //weight: 1
        $x_1_3 = "DownloadToFileSaver" ascii //weight: 1
        $x_1_4 = "Select * from Win32_ComputerSystem" wide //weight: 1
        $x_1_5 = "Host\\host.exe" wide //weight: 1
        $x_1_6 = "toqe.downloader.business" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Bladabindi_DA_2147758771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.DA!MTB"
        threat_id = "2147758771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {41 01 57 dd b6 ff 09 0b 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 b9 00 00 00 2f 00 00 00 43 01 00 00 98 01 00 00 16}  //weight: 3, accuracy: High
        $x_3_2 = "DefaultEventAttribute" ascii //weight: 3
        $x_3_3 = "DebuggerBrowsableAttribute" ascii //weight: 3
        $x_3_4 = "DebuggerBrowsableState" ascii //weight: 3
        $x_3_5 = "QcXFu~jV(;\".resources" ascii //weight: 3
        $x_3_6 = "GetHINSTANCE" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_M_2147760279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.M!MTB"
        threat_id = "2147760279"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 01 00 00 70 0a 17 0b 07 2c 43 73 ?? ?? ?? 0a 0c 73 ?? ?? ?? 0a 0d 09 17 6f ?? ?? ?? 0a 09 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 09 72 ?? ?? ?? 70 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 09 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 26 08 6f ?? ?? ?? 0a 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_DB_2147778550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.DB!MTB"
        threat_id = "2147778550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 72 41 00 00 70 28 01 00 00 06 0c 08 6f 1c 00 00 0a 14 17 8d 01 00 00 01 13 04 11 04 16 02 a2 11 04 6f 1d 00 00 0a 26 de 0a}  //weight: 1, accuracy: High
        $x_1_2 = {0d 1b 8d 16 00 00 01 13 05 11 05 16 09 6f 1e 00 00 0a 6f 1f 00 00 0a a2 11 05 17 28 20 00 00 0a a2 11 05 18 09 6f 21 00 00 0a a2 11 05 19 28 20 00 00 0a a2 11 05 1a 09 6f 22 00 00 0a a2 11 05 28 23 00 00 0a 28 24 00 00 0a 26 de 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_DC_2147778775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.DC!MTB"
        threat_id = "2147778775"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a2 25 1f 1f 11 1f a2 25 1f 20 11 20 a2 28 2b 00 00 0a 28 2c 00 00 0a 13 21 28 2d 00 00 0a 11 21 6f 2e 00 00 0a 13 22 11 22 6f 2f 00 00 0a 14 14 6f 30 00 00 0a 74 27 00 00 01 13 23 2a}  //weight: 1, accuracy: High
        $x_1_2 = {a2 25 7e 46 00 00 04 11 1f a2 25 7e 47 00 00 04 11 20 a2 28 30 00 00 0a 28 31 00 00 0a 13 21 28 32 00 00 0a 11 21 6f 33 00 00 0a 13 22 11 22 6f 34 00 00 0a 14 14 6f 35 00 00 0a 74 22 00 00 01 13 23 2a}  //weight: 1, accuracy: High
        $x_1_3 = {a2 25 1f 1f 11 1d a2 25 1f 20 11 18 a2 28 39 00 00 0a 28 3a 00 00 0a 13 0d 28 3b 00 00 0a 11 0d 6f 3c 00 00 0a 13 33 20 e1 2a 79 2f 80 0c 00 00 04 11 33 20 b8 99 ec 89 80 1e 00 00 04 6f 3d 00 00 0a 14 14 6f 3e 00 00 0a 74 2a 00 00 01 13 05 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Bladabindi_DD_2147778776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.DD!MTB"
        threat_id = "2147778776"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a2 00 06 19 28 2f 00 00 06 a2 00 06 1a 28 30 00 00 06 a2 00 06 1b 28 31 00 00 06 a2 00 06 28 02 00 00 0a 28 03 00 00 0a 6f 04 00 00 0a 6f 05 00 00 0a 14 14 6f 06 00 00 0a 26 00 2a}  //weight: 1, accuracy: High
        $x_1_2 = {a2 00 09 1b 28 31 00 00 06 a2 00 09 28 01 00 00 0a 0a 06 28 02 00 00 0a 0b 28 03 00 00 0a 07 6f 04 00 00 0a 6f 05 00 00 0a 14 14 6f 06 00 00 0a 28 07 00 00 0a 0c 00 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Bladabindi_DE_2147778779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.DE!MTB"
        threat_id = "2147778779"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 1a 00 00 0a 0a 06 28 1b 00 00 0a 0b 07 28 1c 00 00 0a 0c 08 6f 1d 00 00 0a 72 ?? ?? ?? 70 14 6f 1e 00 00 0a 26 20 10 27 00 00 28 1f 00 00 0a 00 14 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {28 23 00 00 0a 72 ?? ?? ?? 70 28 24 00 00 0a 09 28 25 00 00 0a 00 28 23 00 00 0a 72 ?? ?? ?? 70 28 24 00 00 0a 28 26 00 00 0a 26 28 27 00 00 0a 00 00 de 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_DF_2147778920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.DF!MTB"
        threat_id = "2147778920"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 11 06 6f 24 00 00 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f 25 00 00 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f 25 00 00 0a 13 07 11 07 6f 24 00 00 0a 28 03 00 00 06 28 26 00 00 0a 72 ?? ?? ?? 70 28 06 00 00 06 13 08 11 08 17 28 02 00 00 06 00 00 06 17 58 0a 06 17 fe 04 13 0a 11 0a 3a da fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_RMA_2147779790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.RMA!MTB"
        threat_id = "2147779790"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_LoginBtn" ascii //weight: 1
        $x_1_2 = "get_AddPasswordbtn" ascii //weight: 1
        $x_1_3 = "PasswordList" ascii //weight: 1
        $x_1_4 = "CheckPasswordlbl" ascii //weight: 1
        $x_1_5 = "CreateUserNamelbl" ascii //weight: 1
        $x_10_6 = "$b7ef703b-7c3a-44bd-a7d3-52810df7d278" ascii //weight: 10
        $x_10_7 = "\\Documents\\Pass Vault\\AccountPassword" ascii //weight: 10
        $x_10_8 = "\\Documents\\Pass Vault\\Keys.txt" ascii //weight: 10
        $x_10_9 = "\\Documents\\Pass Vault\\KeysDecrypted.txt" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Bladabindi_DJ_2147781866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.DJ!MTB"
        threat_id = "2147781866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {a2 25 17 06 11 ?? 17 28 ?? ?? ?? 0a a2 25 18 07 11 ?? 17 28 ?? ?? ?? 0a a2 25 19 08 11 ?? 17 28 ?? ?? ?? 0a a2 25 1a 09 11 ?? 17 28 ?? ?? ?? 0a a2 25 1b 11 04 11 ?? 17 28 ?? ?? ?? 0a 0b 00 1f ?? 8d ?? ?? ?? 01 25 16 11}  //weight: 10, accuracy: Low
        $x_1_2 = "Convert" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Form1_Load" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_DI_2147781913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.DI!MTB"
        threat_id = "2147781913"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {08 11 04 07 11 04 1e d8 1e 6f ?? ?? ?? 0a 18 28 ?? ?? ?? 0a 9c 11 04 17 d6 13 04 11 04 09 31 e0}  //weight: 20, accuracy: Low
        $x_20_2 = {08 09 07 09 9a 1f 10 28 ?? ?? ?? 0a 9c 09 17 58 0d 09 07 8e 69 3f e6 ff ff ff}  //weight: 20, accuracy: Low
        $x_5_3 = "Convert" ascii //weight: 5
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "Split" ascii //weight: 1
        $x_1_6 = "ToByte" ascii //weight: 1
        $x_1_7 = "CreateInstance" ascii //weight: 1
        $x_1_8 = "Activator" ascii //weight: 1
        $x_1_9 = "BinaryToString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Bladabindi_AH_2147781937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AH!MTB"
        threat_id = "2147781937"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fa 25 33 00 16 ?? ?? 02 ?? ?? ?? 41 ?? ?? ?? 14 ?? ?? ?? 32 ?? ?? ?? 6a ?? ?? ?? 05 ?? ?? ?? 5e ?? ?? ?? 33 ?? ?? ?? 01}  //weight: 10, accuracy: Low
        $x_3_2 = "get_FullName" ascii //weight: 3
        $x_3_3 = "get_IsAlive" ascii //weight: 3
        $x_3_4 = "IsLogging" ascii //weight: 3
        $x_3_5 = "FromBase64String" ascii //weight: 3
        $x_3_6 = "get_ExecutablePath" ascii //weight: 3
        $x_3_7 = "get_CurrentDomain" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Bladabindi_OZ_2147782038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.OZ!MTB"
        threat_id = "2147782038"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 13 07 11 07 16 73 ?? ?? ?? 0a 13 06 1a 8d ?? ?? ?? 01 13 05 11 07 11 07 6f ?? ?? ?? 0a 1b 6a da 6f ?? ?? ?? 0a 11 07 11 05 16 1a 6f ?? ?? ?? 0a 26 11 05 16 28 ?? ?? ?? 0a 13 08 11 07 16 6a 6f ?? ?? ?? 0a 11 08 17 da 17 d6 8d ?? ?? ?? 01 13 04 11 06 11 04 16 11 08}  //weight: 10, accuracy: Low
        $x_1_2 = "ToArray" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "MD5CryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_DL_2147782067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.DL!MTB"
        threat_id = "2147782067"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 19 2b 1a 18 2d 1a 26 26 2b 1d 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0d 1d 2c f0 de 2a 07 2b e4 08 2b e3 6f ?? ?? ?? 0a 2b e1 08 2b e0 16 2d 0c 19 2c 09 08 2c 06 08 6f ?? ?? ?? 0a dc}  //weight: 10, accuracy: Low
        $x_1_2 = "Reader1" ascii //weight: 1
        $x_1_3 = "Reader2" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_JK_2147782200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.JK!MTB"
        threat_id = "2147782200"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 06 07 16 1a 6f ?? ?? ?? 0a 26 07 16 28 ?? ?? ?? 0a 0c 06 16 73 ?? ?? ?? 0a 0d 08 8d ?? ?? ?? 01 13 04 09 11 04 16 08 6f ?? ?? ?? 0a 26 11 04 13 05 de 14 09 2c 06 09 6f ?? ?? ?? 0a dc}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "GetDomain" ascii //weight: 1
        $x_1_4 = "Decompress" ascii //weight: 1
        $x_1_5 = "Payload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ABF_2147782675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ABF!MTB"
        threat_id = "2147782675"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {08 04 07 6e 04 8e b7 6a 5d b7 91 d7 11 05 07 84 95 d7 6e 20 ff 00 00 00 6a 5f b8 0c 11 05 07 84 95 13 06 11 05 07 84 11 05 08 84 95 9e 11 05 08 84 11 06 9e 07 17 d7 0b 07 20 ff 00 00 00 36 c0}  //weight: 10, accuracy: High
        $x_3_2 = "ExecBytes" ascii //weight: 3
        $x_3_3 = "Proper_RC4" ascii //weight: 3
        $x_3_4 = "Beta.Charlie" ascii //weight: 3
        $x_3_5 = "Emit" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_DP_2147783081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.DP!MTB"
        threat_id = "2147783081"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 0a 17 03 6f ?? ?? ?? 0a 13 04 0c 2b 2f 03 08 28 ?? ?? ?? 0a 04 08 04 6f ?? ?? ?? 0a 5d 17 d6 28 ?? ?? ?? 0a da 0d 06 09 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 08 17 d6 0c 08 11 04 31 cc}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_BF_2147786794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.BF!MTB"
        threat_id = "2147786794"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "good.dll" ascii //weight: 1
        $x_1_2 = "GWl6viYdXM26jx9Il1" ascii //weight: 1
        $x_1_3 = "E84FxLMsFJWUWg9u8y" ascii //weight: 1
        $x_1_4 = "Jl4UTh4xAYYyRroj3Q" ascii //weight: 1
        $x_1_5 = "JYOBID6P9wmyV3O2tJ" ascii //weight: 1
        $x_1_6 = "xJWBUWg9u" ascii //weight: 1
        $x_1_7 = "QlQdwCH6y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ASD_2147787520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ASD!MTB"
        threat_id = "2147787520"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "/c start /I" ascii //weight: 3
        $x_3_2 = "hackacademy" ascii //weight: 3
        $x_3_3 = "DownloadString" ascii //weight: 3
        $x_3_4 = "DownloadData" ascii //weight: 3
        $x_3_5 = "Askar_Loader" ascii //weight: 3
        $x_3_6 = {fa 01 33 00 16 00 00 01 00 00 00 25 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? 0a}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_EV_2147794269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.EV!MTB"
        threat_id = "2147794269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "TestCrypter" ascii //weight: 3
        $x_3_2 = "d3cr4pt" ascii //weight: 3
        $x_3_3 = "dcrp" ascii //weight: 3
        $x_3_4 = "DownloadFile" ascii //weight: 3
        $x_3_5 = "cr4pt3d" ascii //weight: 3
        $x_3_6 = "Debug\\TestCrypter0.pdb" ascii //weight: 3
        $x_3_7 = "FromBase64String" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_BTGF_2147794615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.BTGF!MTB"
        threat_id = "2147794615"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 02 72 66 64 02 70 72 72 64 02 70 28 1d 00 00 0a 0a 06 6f 1e 00 00 0a 1e 5b 8d 24 00 00 01 0b 16 0d 2b 19 00 07 09 06 09 1e 5a 1e 6f 1f 00 00 0a 18 28 20 00 00 0a 9c 00 09 17 58 0d 09 07 8e 69 17 59 fe 02 16 fe 01 13 04 11 04 2d d6}  //weight: 1, accuracy: High
        $x_1_2 = {00 12 00 fe 15 05 00 00 02 12 00 02 28 1a 00 00 0a 7d 06 00 00 04 12 00 06 7b 06 00 00 04 6f 1b 00 00 0a 7d 07 00 00 04 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_QW_2147794960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.QW!MTB"
        threat_id = "2147794960"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "MouseState" ascii //weight: 3
        $x_3_2 = "svchost.Windows" ascii //weight: 3
        $x_3_3 = "WebClient" ascii //weight: 3
        $x_3_4 = "C:\\Users\\AShoky" ascii //weight: 3
        $x_3_5 = "dr ali" ascii //weight: 3
        $x_3_6 = "svchost.pdb" ascii //weight: 3
        $x_3_7 = "$this.Text" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_OEOE_2147795092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.OEOE!MTB"
        threat_id = "2147795092"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 1f 2a 1f 30 28 ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 06 0c 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 14 14 6f ?? ?? ?? 0a 26 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {06 0a 06 02 7d ?? ?? ?? 04 00 16 06 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 25 2d 17 26 7e ?? ?? ?? 04 fe ?? ?? ?? ?? 06 73 ?? ?? ?? 0a 25 80 ?? ?? ?? 04 28 ?? ?? ?? 2b 06 fe ?? ?? ?? ?? 06 73 ?? ?? ?? 0a 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0b 2b 00 07 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_DY_2147795227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.DY!MTB"
        threat_id = "2147795227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "adfasdas" ascii //weight: 1
        $x_1_2 = "CASH_COUNTER_PAYMENT_ICON_192435" wide //weight: 1
        $x_1_3 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_4 = "ResolveSignature" ascii //weight: 1
        $x_1_5 = "get_CurrentDomain" ascii //weight: 1
        $x_1_6 = "GetManifestResourceStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SWER_2147795745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SWER!MTB"
        threat_id = "2147795745"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ScreenLock" ascii //weight: 1
        $x_1_2 = "Server send thread exception" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "This is a reverse shell tool, which gives access to this machine remotely from anywhere" ascii //weight: 1
        $x_1_5 = "Connected to chat" ascii //weight: 1
        $x_1_6 = "IPAddress" ascii //weight: 1
        $x_1_7 = "WebClient" ascii //weight: 1
        $x_1_8 = "System.Net.Sockets" ascii //weight: 1
        $x_1_9 = "WriteAllBytes" ascii //weight: 1
        $x_1_10 = "StringBuilder" ascii //weight: 1
        $x_1_11 = "SpecialFolder" ascii //weight: 1
        $x_1_12 = "RemoteShellStream" ascii //weight: 1
        $x_1_13 = "ComputeStringHash" ascii //weight: 1
        $x_1_14 = "get_ExecutablePath" ascii //weight: 1
        $x_1_15 = "StartFileReceive" ascii //weight: 1
        $x_1_16 = "get_HardwareUsageActive" ascii //weight: 1
        $x_1_17 = "set_RemoteShellActive" ascii //weight: 1
        $x_1_18 = "AntiVirusTag" ascii //weight: 1
        $x_1_19 = "ClipboardType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_OEGH_2147795820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.OEGH!MTB"
        threat_id = "2147795820"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kernel32" ascii //weight: 1
        $x_1_2 = "WriteByte" ascii //weight: 1
        $x_1_3 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "CompareString" ascii //weight: 1
        $x_1_6 = "ToString" ascii //weight: 1
        $x_1_7 = "OverflowException" ascii //weight: 1
        $x_1_8 = "StreamWriter" ascii //weight: 1
        $x_1_9 = "VirtualProtect" ascii //weight: 1
        $x_1_10 = "WebClient" ascii //weight: 1
        $x_1_11 = "RtlMoveMemory" ascii //weight: 1
        $x_1_12 = "https://cdn.discordapp.com/attachment" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SWERRER_2147795821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SWERRER!MTB"
        threat_id = "2147795821"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c5 81 c0 93 00 00 00 b9 ca 05 00 00 ba ?? ?? ?? ?? 30 10 40 49 0f 85 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AB_2147797105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AB!MTB"
        threat_id = "2147797105"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 e3 00 00 70 72 bf 00 00 70 6f ?? ?? ?? 0a 00 73 4a 00 00 0a 0d 09 6f ?? ?? ?? 0a 72 bf 00 00 70 6f ?? ?? ?? 0a 00 09 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "ziroland game.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AB_2147797105_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AB!MTB"
        threat_id = "2147797105"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 0f 00 00 0a 0d 09 06 1f 10 6f 10 00 00 0a 6f 11 00 00 0a 09 06 1f 10 6f 10 00 00 0a 6f 12 00 00 0a 09 6f 13 00 00 0a 02 16 02 8e 69 6f 14 00 00 0a 0b 07 8e 69 1f 11 da 17 d6 8d 06 00 00 01 0c 07 1f 10 08 16 07 8e 69 1f 10 da 28 15 00 00 0a 08 2a}  //weight: 1, accuracy: High
        $x_1_2 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AB_2147797105_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AB!MTB"
        threat_id = "2147797105"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {fa 25 33 00 16 00 00 01 00 00 00 b9 00 00 00 3a 00 00 00 d7 00 00 00 02 03 00 00 08 01 00 00 74 01 00 00 13 00 00 00 07 01 00 00 01 00 00 00 02 00 00 00 4c 00 00 00 0f 00 00 00 44}  //weight: 10, accuracy: High
        $x_3_2 = "set_UseSystemPasswordChar" ascii //weight: 3
        $x_3_3 = "RunWorkerCompletedEventHandler" ascii //weight: 3
        $x_3_4 = "TrackDecrPrmKey" ascii //weight: 3
        $x_3_5 = "DownloadFile" ascii //weight: 3
        $x_3_6 = "download_link" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_EA_2147797347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.EA!MTB"
        threat_id = "2147797347"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$c15ee8e2-e253-8275-43c6-694f88155b4a" ascii //weight: 20
        $x_20_2 = "$81ae15cb-c6f2-796b-98b4-cea5b5457446" ascii //weight: 20
        $x_20_3 = "$ba6ed186-4616-a35e-0fb6-c8de57ddae1e" ascii //weight: 20
        $x_20_4 = "$14f9f498-9b84-c764-f9ec-37c775deed34" ascii //weight: 20
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_9 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggingModes" ascii //weight: 1
        $x_1_12 = "FromBase64String" ascii //weight: 1
        $x_1_13 = "CreateInstance" ascii //weight: 1
        $x_1_14 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Bladabindi_EB_2147797348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.EB!MTB"
        threat_id = "2147797348"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 1e 58 4a 93 11 04 33 0e 06 06 4a 1f 3a 5a 06 1e 58 4a 58 54 2b 12 06 1e 58 06 1e 58 4a 17 58 54 06 1e 58 4a 1f 3a 32 d2 06 1a 58 06 1a 58 4a 17 59 54 16 3a 9d 00 00 00 06 1a 58 4a 16 2f 9a}  //weight: 10, accuracy: High
        $x_3_2 = "ZSDRTGHUJKLOIKJHGF" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_EB_2147797348_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.EB!MTB"
        threat_id = "2147797348"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$c459ec24-f2b4-9e86-9ae4-b93942c90e96" ascii //weight: 20
        $x_20_2 = "$ac807405-5c25-1a28-1ac1-4d173e748b32" ascii //weight: 20
        $x_20_3 = "$c414314e-1b71-45bc-bf28-fd196e33dd2a" ascii //weight: 20
        $x_20_4 = "$948a9c01-b6cd-431d-86ed-1575dec3d852" ascii //weight: 20
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_9 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggingModes" ascii //weight: 1
        $x_1_12 = "FromBase64String" ascii //weight: 1
        $x_1_13 = "CreateInstance" ascii //weight: 1
        $x_1_14 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Bladabindi_V_2147797787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.V!MTB"
        threat_id = "2147797787"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "OneDrive.CSGO_ERR.resources" ascii //weight: 1
        $x_1_2 = "$aecd6c1c-bdf8-4245-a7f4-78927fd578cd" ascii //weight: 1
        $x_1_3 = {50 68 6f 65 6e 69 78 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 4f 6e 65 44 72 69 76 65 5c 4f 6e 65 44 72 69 76 65 5c 6f 62 6a 5c [0-8] 5c 4f 6e 65 44 72 69 76 65 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_4 = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\StartupApproved\\\\Run" wide //weight: 1
        $x_1_5 = "get_ProductName" ascii //weight: 1
        $x_1_6 = "GetProcessesByName" ascii //weight: 1
        $x_1_7 = "get_StartupPath" ascii //weight: 1
        $x_1_8 = "timer1_Tick" ascii //weight: 1
        $x_1_9 = "SetAutoRun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_OET_2147797878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.OET!MTB"
        threat_id = "2147797878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ec632fd9-1694-4f4a-9bff-f20600e37981" ascii //weight: 1
        $x_1_2 = "get_WebServices" ascii //weight: 1
        $x_1_3 = "Hashtable" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_6 = "ShutdownMode" ascii //weight: 1
        $x_1_7 = "$e0c16aab-f66b-41a0-b61a-199b9a0de959" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_STRR_2147808056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.STRR!MTB"
        threat_id = "2147808056"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TVqQAAMAAAAEAAAA//" ascii //weight: 1
        $x_1_2 = "IGNhbm5vdCBiZSBydW4gaW4g" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "FrameworkDisplayName" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "get_Assembly" ascii //weight: 1
        $x_1_7 = "$f665918b-b2a4-4bb3-968d-7570b46fb478" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_STRR_2147808056_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.STRR!MTB"
        threat_id = "2147808056"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyPressEventArgs" ascii //weight: 1
        $x_1_2 = "BinaryMask" ascii //weight: 1
        $x_1_3 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_4 = "HideModuleNameAttribute" ascii //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
        $x_1_6 = "LoadFile" ascii //weight: 1
        $x_1_7 = "SmtpClient" ascii //weight: 1
        $x_1_8 = "ResumeLayout" ascii //weight: 1
        $x_1_9 = "cubel.userspprtaddrss@gmail.com" ascii //weight: 1
        $x_1_10 = "$8ba29b8d-a627-45c0-aaff-a7076793538f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MC_2147809191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MC!MTB"
        threat_id = "2147809191"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 11 06 16 72 ?? ?? ?? 70 a2 11 06 0c 07 08 16 6f ?? ?? ?? 0a 0d 17 13 04 2b 3f 00 02 09 11 04 9a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 13 05 06 09 11 04 17 58 9a 28 ?? ?? ?? 0a 11 05 28 ?? ?? ?? 0a 00 06 09 11 04 17 58 9a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 26 00 11 04 18 58 13 04 11 04 09 28 ?? ?? ?? 2b 17 59 fe 04 13 07 11 07}  //weight: 1, accuracy: Low
        $x_1_2 = "GetTempPath" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Kill" ascii //weight: 1
        $x_1_5 = "RijndaelManaged" ascii //weight: 1
        $x_1_6 = "Unsecure" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "TransformFinalBlock" ascii //weight: 1
        $x_1_9 = "set_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_XKS_2147809848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.XKS!MTB"
        threat_id = "2147809848"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 40 00 00 0a 0a 00 06 28 ?? ?? ?? 06 8d 3a 00 00 01 25 d0 b6 01 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 06 28 ?? ?? ?? 06 8d 3a 00 00 01 25 d0 b7 01 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 02 28 ?? ?? ?? 06 02 8e 69 6f ?? ?? ?? 0a 0b de 10 06 14 fe 01 0c 08 2d 07 06 6f ?? ?? ?? 0a 00 dc 00 07 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SNGM_2147809850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SNGM!MTB"
        threat_id = "2147809850"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "fikralgodec" ascii //weight: 2
        $x_2_2 = "StrReverse" ascii //weight: 2
        $x_2_3 = "ToByte" ascii //weight: 2
        $x_2_4 = "GetString" ascii //weight: 2
        $x_2_5 = {00 7a 7a 7a 7a 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_DNGM_2147809851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.DNGM!MTB"
        threat_id = "2147809851"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 07 72 0d 00 00 70 15 16 28 ?? ?? ?? 0a 0c 00 08 8e 69 17 da 17 d6 8d 2a 00 00 01 0d 08 8e 69 18 da 13 04 16 13 05 2b 15 00 09 11 05 08 11 05 9a 28 ?? ?? ?? 0a 9c 00 11 05 17 d6 13 05 11 05 11 04 fe 02 16 fe 01 13 06 11 06 2d dc 09 13 07 2b 00 11 07 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_JNGM_2147809852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.JNGM!MTB"
        threat_id = "2147809852"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Md5Decrypt" ascii //weight: 2
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_2_4 = "RSMD_EC" ascii //weight: 2
        $x_1_5 = {00 44 65 63 5f 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 72 61 6a 61 77 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_LKS_2147810916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.LKS!MTB"
        threat_id = "2147810916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 08 11 09 11 07 11 0a 25 17 58 13 0a 91 08 61 d2 9c 09 17 5f 17 33 07 11 0a 11 04 58 13 0a 08 1b 64 08 1f 1b 62 60 1d 5a 0c 09 17 64 09 1f 1f 62 60 0d 11 09 17 58 13 09 11 09 6a 20 00 2e 08 00 6a 32 bc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_GRM_2147810917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.GRM!MTB"
        threat_id = "2147810917"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 23 01 00 0a 0a 00 06 28 ?? ?? ?? 06 8d 8f 00 00 01 25 d0 d0 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 06 28 ?? ?? ?? 06 8d 8f 00 00 01 25 d0 d1 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 02 28 ?? ?? ?? 06 02 8e 69 6f ?? ?? ?? 0a 0b de 10 06 14 fe 01 0c 08 2d 07 06 6f ?? ?? ?? 0a 00 dc 00 07 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ZAREGA_2147811640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ZAREGA!MTB"
        threat_id = "2147811640"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 06 11 06 20 00 01 00 00 6f ?? ?? ?? 0a 11 06 17 6f ?? ?? ?? 0a 11 06 0c 03 2d 11 08 07 1f 10 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 2b 0f 08 07 1f 10 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0d 73 31 00 00 0a 13 04 11 04 09 17 73 32 00 00 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_HYAL_2147813523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.HYAL!MTB"
        threat_id = "2147813523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 11 05 03 11 05 91 06 61 09 08 91 61 b4 9c 08 04 6f ?? ?? ?? 0a 17 da fe 01 13 07 11 07 2c 04 16 0c 2b 05 00 08 17 d6 0c 00 11 05 17 d6 13 05 11 05 11 06 13 08 11 08 31 c6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SSQ_2147815744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SSQ!MTB"
        threat_id = "2147815744"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 01 00 00 70 0a 06 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 73 15 00 00 0a 20 bc 9e 00 00 1f 30 28 ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 06 0c 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 14 14 6f ?? ?? ?? 0a 26 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AW_2147816701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AW!MTB"
        threat_id = "2147816701"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {01 57 15 a2 09 09 01 00 00 00 00 00 00 00 00 00 00 01 00 00 00 2f}  //weight: 3, accuracy: High
        $x_3_2 = "System.Threading.Tasks" ascii //weight: 3
        $x_3_3 = "System.Net.Http" ascii //weight: 3
        $x_3_4 = "ProcessStartInfo" ascii //weight: 3
        $x_3_5 = "HttpClient" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MR_2147817026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MR!MTB"
        threat_id = "2147817026"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "o24zi01O2pKl" wide //weight: 1
        $x_1_2 = "+96OxDb02T5aP" wide //weight: 1
        $x_1_3 = "+qAWtgEpi58W" wide //weight: 1
        $x_1_4 = "+ltLw2t0pi0u4UU" wide //weight: 1
        $x_1_5 = "+FdE8x9BH6GTpJL" wide //weight: 1
        $x_1_6 = "Xx4aFjCfuUD0Fh" wide //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "CreateDecryptor" ascii //weight: 1
        $x_1_9 = "GetBytes" ascii //weight: 1
        $x_1_10 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_RPF_2147817196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.RPF!MTB"
        threat_id = "2147817196"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "void.cat" wide //weight: 1
        $x_1_2 = "FuckinPizdec.core.Config" ascii //weight: 1
        $x_1_3 = "/C choice /C Y /N /D Y /T 5 & Del" wide //weight: 1
        $x_1_4 = "cmd.exe" wide //weight: 1
        $x_1_5 = "taskmgr" wide //weight: 1
        $x_1_6 = "processhacker" wide //weight: 1
        $x_1_7 = "regmon" wide //weight: 1
        $x_1_8 = "filemon" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_RPG_2147817197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.RPG!MTB"
        threat_id = "2147817197"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "onion.ws/quace.exe" wide //weight: 1
        $x_1_2 = "AppData\\Local\\NvidiaGefroce.exe" wide //weight: 1
        $x_1_3 = "runas" wide //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_1_5 = "Concat" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
        $x_1_7 = "Rambo" ascii //weight: 1
        $x_1_8 = "Mayonnaise" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_BIL_2147817274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.BIL!MTB"
        threat_id = "2147817274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0a 11 06 11 0b 94 d6 11 07 11 0b 94 d6 20 00 01 00 00 5d 13 0a 11 06 11 0b 94 13 0e 11 06 11 0b 11 06 11 0a 94 9e 11 06 11 0a 11 0e 9e 12 0b 28 ?? ?? ?? 0a 11 0b 17 da 28 ?? ?? ?? 0a 26 00 11 0b 20 ff 00 00 00 fe 02 16 fe 01 13 0f 11 0f 2d ae}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_RPK_2147817370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.RPK!MTB"
        threat_id = "2147817370"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 77 00 77 00 2e 00 75 00 70 00 6c 00 6f 00 6f 00 64 00 65 00 72 00 2e 00 6e 00 65 00 74 00 [0-128] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = "DownloadString" wide //weight: 1
        $x_1_3 = "Convert" ascii //weight: 1
        $x_1_4 = "LateGet" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_RPL_2147817490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.RPL!MTB"
        threat_id = "2147817490"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mrRoboto" ascii //weight: 1
        $x_1_2 = "Botnet" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "download" wide //weight: 1
        $x_1_5 = "execute" wide //weight: 1
        $x_1_6 = "destroy" wide //weight: 1
        $x_1_7 = "irc.freenode.net" wide //weight: 1
        $x_1_8 = "WebClient" ascii //weight: 1
        $x_1_9 = "DownloadFile" ascii //weight: 1
        $x_1_10 = "SpecialFolder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ZXH_2147817944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ZXH!MTB"
        threat_id = "2147817944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 06 1e 8d ?? ?? ?? 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 06 1f 18 8d ?? ?? ?? 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0b de 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AM_2147818258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AM!MTB"
        threat_id = "2147818258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taifilemoi1" ascii //weight: 1
        $x_1_2 = "Updata.exe" ascii //weight: 1
        $x_1_3 = "check.txt" wide //weight: 1
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "taimuti" ascii //weight: 1
        $x_1_6 = "get_Khaki" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AM_2147818258_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AM!MTB"
        threat_id = "2147818258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fa 25 33 00 16 00 00 01 00 00 00 2a 00 00 00 0c 00 00 00 2b 00 00 00 36 00 00 00 32 00 00 00 10}  //weight: 2, accuracy: High
        $x_2_2 = "Ruffle Group Application" ascii //weight: 2
        $x_2_3 = "ReverseDecode" ascii //weight: 2
        $x_2_4 = "BitTreeDecoder" ascii //weight: 2
        $x_2_5 = "Decompress" ascii //weight: 2
        $x_2_6 = "ConfusedByAttribute" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NQG_2147818340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NQG!MTB"
        threat_id = "2147818340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 41 00 00 70 0a 73 1e 00 00 0a 0b 16 0c 2b 37 00 06 28 ?? ?? ?? 0a 0d 03 08 94 06 6f ?? ?? ?? 0a 20 80 00 00 00 61 5b 13 04 11 04 09 20 00 01 00 00 5a 16 60 59 d2 13 05 07 11 05 6f ?? ?? ?? 0a 00 00 08 17 58 0c 08 03 8e 69 fe 04 13 06 11 06 2d bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_UXO_2147818341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.UXO!MTB"
        threat_id = "2147818341"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 04 02 11 04 91 06 11 04 06 8e b7 5d 91 61 08 11 04 08 8e b7 5d 91 61 9c 11 04 17 d6 13 04 11 04 11 05 31 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ME_2147819025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ME!MTB"
        threat_id = "2147819025"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 05 11 05 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 05 11 05 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 05 11 05 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 05 11 05 28 ?? ?? ?? 0a 13 06 28 ?? ?? ?? 0a 11 06 6f ?? ?? ?? 0a 13 07 72 ?? ?? ?? 70 13 08 11 08 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 13 08 11 08 28 ?? ?? ?? 0a 13 09 28 ?? ?? ?? 0a 11 09 6f ?? ?? ?? 0a 13 0a 7e ?? ?? ?? 0a 26 11 04 28 ?? ?? ?? 0a 13 0b 28 ?? ?? ?? 0a 11 0b 6f ?? ?? ?? 0a 13 0c 09 28 ?? ?? ?? 0a 13 0d 28 ?? ?? ?? 0a 11 0d 6f ?? ?? ?? 0a 13 0e 73 ?? ?? ?? 0a 11 0e 28 ?? ?? ?? 0a 13 0f 06 11 0c}  //weight: 10, accuracy: Low
        $x_1_2 = "GetUserInput" ascii //weight: 1
        $x_1_3 = "StrReverse" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_RPN_2147819258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.RPN!MTB"
        threat_id = "2147819258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 20 ff 00 00 00 5f 2b 1d 03 6f 7c 00 00 0a 0c 2b 17 08 06 08 06 93 02 7b 11 00 00 04 07 91 04 60 61 d1 9d 2b 03 0b 2b e0 06 17 59 25 0a 16 2f 02 2b 05 2b dd 0a 2b c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NU_2147819703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NU!MTB"
        threat_id = "2147819703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 07 6f ?? ?? ?? 0a 00 08 18 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d 09 13 04 2b}  //weight: 1, accuracy: Low
        $x_1_2 = {57 95 a2 29 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 56 00 00 00 09 00 00 00 0f 00 00 00 17 00 00 00 05 00 00 00 76 00 00 00 18 00 00 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NV_2147820300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NV!MTB"
        threat_id = "2147820300"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 84 95 d7 6e 20 ff 00 00 00 6a 5f b7 95 61 86 9c}  //weight: 5, accuracy: High
        $x_3_2 = {08 84 95 d7 6e 20 ff 00 00 00 6a 5f b8 0d 1b}  //weight: 3, accuracy: High
        $x_2_3 = {08 6e 17 6a d6 20 ff 00 00 00 6a 5f b8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NV_2147820300_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NV!MTB"
        threat_id = "2147820300"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 07 16 28 ?? ?? ?? 0a 0c 06 16 73 ?? ?? ?? 0a 0d 08 8d ?? ?? ?? 01 13 04}  //weight: 1, accuracy: Low
        $x_1_2 = {57 b5 a2 3d 09 07 00 00 00 00 00 00 00 00 00 00 02 00 00 00 67 00 00 00 18 00 00 00 26 00 00 00 8b 00 00 00 26 00 00 00 71 00 00 00 24 00 00 00 05}  //weight: 1, accuracy: High
        $x_1_3 = "332be4d89650" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_RPE_2147820301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.RPE!MTB"
        threat_id = "2147820301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 6c 9c 06 1e 1f 61 9c 06 1f 09 1f 75 9c 06 1f 0a 1f 72 9c 06 1f 0b 1f 65 9c 06 1f 0c 1f 6e 9c 06 1f 0d 1f 74 9c 06 1f 0e 1f 70 9c 06 1f 0f 1f 72 9c 06 1f 10 1f 6f 9c 06 1f 11 1f 74 9c 06 1f 12 1f 65 9c 06 1f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NW_2147820440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NW!MTB"
        threat_id = "2147820440"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 2d 11 2b 1f 2d 0d 16 2d f6 2b 1b 2b 1c 2b 1d 2b 1e 2b 0a 2b 21 2b 22}  //weight: 1, accuracy: High
        $x_1_2 = {9d a2 3f 09 1f 00 00 00 98 00 33 00 16 00 00 01 00 00 00 c2 00 00 00 2d 00 00 00 48 01 00 00 f7 00 00 00 b9 00 00 00 5d 01 00 00 34}  //weight: 1, accuracy: High
        $x_1_3 = "280da54e2344" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NG_2147822940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NG!MTB"
        threat_id = "2147822940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e 30 00 00 04 0e 06 17 59 95 58 0e 05 28 ?? 02 00 06 58 54}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NG_2147822940_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NG!MTB"
        threat_id = "2147822940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 09 11 09 16 72 ?? ?? ?? ?? a2 00 11 09 16 6f ?? ?? ?? ?? 13 07 11 07 16 9a 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0c 11 07 8e b7 19 2e 06 11 07 17 9a 2b 0e 11 07 17 9a 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 10 01 06 11 04 28 ?? ?? ?? ?? 04 6f [0-21] 0a 00 06 08 28 ?? ?? ?? ?? ?? ?? ?? ?? 0a 00 06 17}  //weight: 1, accuracy: Low
        $x_1_2 = {15 a2 09 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 7b 00 00 00 10 00 00 00 35 00 00 00 86 00 00 00 44 00 00 00 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_EWL_2147823953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.EWL!MTB"
        threat_id = "2147823953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 30 59 c5 7e 30 35 00 35 00 69 97 38 00 69 97 69 97 38 00 7e 30 38 00 7e 30 36 00 7e 30 37 00 7e 30 45 c5 7e 30 33 00 7e 30 35 00 35 00 69 97 38 00}  //weight: 1, accuracy: High
        $x_1_2 = {c5 69 97 38 00 7e 30 59 c5 7e 30 44 c5 7e 30 37 00 7e 30 7e 30 69 97 59 c5 7e 30 4c c5 69 97 35 00 35 00 69 97 69 97 35 00 33 00 32 00 69 97}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_B_2147824022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.B!MTB"
        threat_id = "2147824022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://soft.fileshipoo.com/ford/submit_ticket.php" wide //weight: 1
        $x_1_2 = "schtasks /create /F  /sc minute /mo 1 /tn \"InetlMeFWSrevice" wide //weight: 1
        $x_1_3 = "Manger Folder.exe" wide //weight: 1
        $x_1_4 = "Folder\\Folder.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NEC_2147824174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NEC!MTB"
        threat_id = "2147824174"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e1}  //weight: 1, accuracy: High
        $x_1_2 = "pyvelrU+SBPM/2MWEftieA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_OEK_2147824715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.OEK!MTB"
        threat_id = "2147824715"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 06 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 07 06 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0c 08 8e 69 1f 10 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NEI_2147825937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NEI!MTB"
        threat_id = "2147825937"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 06 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 06 28 ?? 00 00 0a 20 ?? 04 00 00 28 ?? 00 00 0a 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 7e ?? 00 00 0a 26 de 03}  //weight: 1, accuracy: Low
        $x_1_2 = "RegAsm.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NYK_2147827608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NYK!MTB"
        threat_id = "2147827608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 b8 88 00 00 28 21 00 00 0a 28 40 00 00 0a 0d 16 13 04 2b 1f 09 11 04 9a}  //weight: 1, accuracy: High
        $x_1_2 = {15 a2 15 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 4e 00 00 00 21 00 00 00 20 00 00 00 3c 03 00 00 12 00 00 00 77 00 00 00 16 00 00 00 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NEJ_2147827665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NEJ!MTB"
        threat_id = "2147827665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 04 02 1f 0c 11 04 16 09 28 bd 00 00 0a 12 04 09 28 04 00 00 2b 06 07 08 28 b9 00 00 0a 11 04 6f be 00 00 0a 73 4b 00 00 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ABO_2147827752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ABO!MTB"
        threat_id = "2147827752"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 14 72 17 ?? ?? 70 19 8d ?? ?? ?? 01 0a 06 16 72 ?? ?? ?? 70 a2 00 06 17 16 8c ?? ?? ?? 01 a2 00 06 18 17 8c ?? ?? ?? 01 a2 00 06 14 3b 00 72 ?? ?? ?? 70 72 ?? ?? ?? 70 28 7e}  //weight: 4, accuracy: Low
        $x_1_2 = "WebServices" ascii //weight: 1
        $x_1_3 = "KillHungProcess" ascii //weight: 1
        $x_1_4 = "taskkill" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NYL_2147827886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NYL!MTB"
        threat_id = "2147827886"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$e7cba1a0-d734-4268-ba10-4ae8b49d7200" ascii //weight: 1
        $x_1_2 = {57 95 a2 3f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 9a 00 00 00 1c 00 00 00 58 00 00 00 78 01 00 00 3b 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {0a 01 00 00 7c 00 00 00 02 00 00 00 38 00 00 00 07 00 00 00 28 00 00 00 3e 00 00 00 08 00 00 00 01 00 00 00 0c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "Anon_SE.Resources.resource" ascii //weight: 1
        $x_1_5 = "ConfuserEx v1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NEG_2147828124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NEG!MTB"
        threat_id = "2147828124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 72 01 00 00 70 6f 04 00 00 0a 0a de 0a 07 2c 06 07 6f 05 00 00 0a dc 28 06 00 00 0a 72 ?? 00 00 70 28 07 00 00 0a 06 28 08 00 00 0a 20 b0 04 00 00 28 09 00 00 0a 28 06 00 00 0a 72 ?? 00 00 70 28 07 00 00 0a 28 0a 00 00 0a 26 7e 0b 00 00 0a 26 de 03}  //weight: 1, accuracy: Low
        $x_1_2 = "healthpyservices.com" wide //weight: 1
        $x_1_3 = "RegAsm.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NEK_2147829225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NEK!MTB"
        threat_id = "2147829225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "143a9202-af5c-4d93-82f9-6ac344c4582a" ascii //weight: 1
        $x_1_2 = "SFU4mbT3GMret7THonf" ascii //weight: 1
        $x_1_3 = "fieldimpl3" ascii //weight: 1
        $x_1_4 = "b77a5c561934e089" ascii //weight: 1
        $x_1_5 = "$$method0x6000012-1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NX_2147830429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NX!MTB"
        threat_id = "2147830429"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 16 6f ?? ?? ?? 0a 13 04 12 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 d6 0d 09 08 31 dc}  //weight: 1, accuracy: Low
        $x_1_2 = "a.top4top.io/p_2428mn69" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NEM_2147830642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NEM!MTB"
        threat_id = "2147830642"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 16 11 05 6f 75 00 00 0a 00 08 06 16 06 8e b7 6f 81 00 00 0a 13 05 00 11 05 16 fe 02 13 06 11 06}  //weight: 1, accuracy: High
        $x_1_2 = "cmd.exe /k ping 0 & del" wide //weight: 1
        $x_1_3 = "RunFileFromLink" wide //weight: 1
        $x_1_4 = "SELECT * FROM FirewallProduct" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NEO_2147831357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NEO!MTB"
        threat_id = "2147831357"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 1d 00 00 0a 72 01 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c 28 20 00 00 0a 28 21 00 00 0a de 00 28 1d 00 00 0a 72 ?? 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c 28 20 00 00 0a 28 21 00 00 0a de 00}  //weight: 1, accuracy: Low
        $x_1_2 = "JawrHJfWf" wide //weight: 1
        $x_1_3 = "LOST.DIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_PSC_2147831468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PSC!MTB"
        threat_id = "2147831468"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 28 30 00 00 0a 2d 12 06 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 06 28 ?? ?? ?? 0a 26 06 28 ?? ?? ?? 0a 2c 0e 06 18 28 ?? ?? ?? 0a 06 28 ?? ?? ?? 0a 26 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 0c 28 ?? ?? ?? 06 0b 08 28 ?? ?? ?? 0a 2c 07 08}  //weight: 5, accuracy: Low
        $x_1_2 = "GetObject" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NEP_2147833296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NEP!MTB"
        threat_id = "2147833296"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "B469382C7D6D78AB426283E2" ascii //weight: 5
        $x_5_2 = "bb8050c4-558c-49fc-946d-c7ac9883c02e" ascii //weight: 5
        $x_5_3 = "xinheyun.com" wide //weight: 5
        $x_5_4 = "SupmeaEzCad" ascii //weight: 5
        $x_2_5 = "Newtonsoft.Json" ascii //weight: 2
        $x_2_6 = "lmc1_MarkEntityFly" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MF_2147834998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MF!MTB"
        threat_id = "2147834998"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "tdgm.exe" wide //weight: 5
        $x_5_2 = "sexy" wide //weight: 5
        $x_5_3 = "OQVwu.dll" ascii //weight: 5
        $x_5_4 = {57 4c 6d 51 75 00 66 77 73 72 4d 2e 64 6c 6c 00 76 67 4d 62 69 00 67 42 66 53 47 00 59 56 57 63 75 00 71 47 4f 78 47 00 42 4b 77 65 47 00 54 75 47 41 52}  //weight: 5, accuracy: High
        $x_1_5 = "SELECT * FROM AntivirusProduct" wide //weight: 1
        $x_1_6 = "Screenshot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NWZ_2147835581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NWZ!MTB"
        threat_id = "2147835581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {a2 25 17 08 a2 25 13 05 14 14 18 ?? ?? ?? ?? ?? 25 17 17 9c 25}  //weight: 3, accuracy: Low
        $x_3_2 = "t_AAAAAAAAAAAAAAAAAAAAA" ascii //weight: 3
        $x_3_3 = "PXX00001" ascii //weight: 3
        $x_3_4 = "PXX00002" ascii //weight: 3
        $x_3_5 = "PXX00003" ascii //weight: 3
        $x_3_6 = "PXX00004" ascii //weight: 3
        $x_1_7 = "GetMethod" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NZC_2147836543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NZC!MTB"
        threat_id = "2147836543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 06 95 06 11 06 1f 0f 5f 95 61 13 07 06 11 06 1f 0f 5f 06}  //weight: 1, accuracy: High
        $x_1_2 = {20 de a8 01 00 26 20 de a8 01 00 8d 18 00 00 01 25 d0 02 00 00 04}  //weight: 1, accuracy: High
        $x_1_3 = "585-8f03-332c5b5db41f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_S_2147838415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.S!MTB"
        threat_id = "2147838415"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {85 c9 7c 2a 8b 35 88 2c 41 00 b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8b 15 24 20 41 00 8d 04 80 03 c0 2b d0 8a 04 0a 30 04 0e 41 3b 0d a0 2c 41 00 76 c9}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_S_2147838415_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.S!MTB"
        threat_id = "2147838415"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 34 00 00 0a 72 47 01 00 70 28 35 00 00 0a 17 8d 28 00 00 01 25 16 1f 3a 9d 6f 36 00 00 0a 0a 06 8e 69 17 da 0c 16 0b 2b 14 06 16 9a 80 0e 00 00 04 06 17 9a 80 18 00 00 04 07 17 d6 0b 07 08 31 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SC_2147838497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SC!MTB"
        threat_id = "2147838497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHELL.pdb" ascii //weight: 1
        $x_1_2 = "SHELL.exe" ascii //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "Monitor" ascii //weight: 1
        $x_1_5 = "C:\\Users\\xD\\source\\repos\\SHELL\\SHELL\\obj\\Release\\SHELL.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NEAA_2147838573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NEAA!MTB"
        threat_id = "2147838573"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {74 24 00 00 01 6f 20 00 00 0a 07 6f 21 00 00 0a 2c 12 2b 06 0b 2b ba 0c 2b c0 08 16 6f 1f 00 00 0a 0a 2b 6d 08 17}  //weight: 10, accuracy: High
        $x_5_2 = {2b 03 2b 08 2a 28 04 00 00 06 2b f6 28 1d 00 00 0a 2b f1}  //weight: 5, accuracy: High
        $x_2_3 = "Powered by SmartAssembly 8.1.0.4892" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_RDA_2147839822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.RDA!MTB"
        threat_id = "2147839822"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 02 07 91 18 63 17 5f d2 9c 07 17 58 0b 07 02 8e 69}  //weight: 2, accuracy: High
        $x_1_2 = "BasedAntiVT.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NEAB_2147840113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NEAB!MTB"
        threat_id = "2147840113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 0e 00 00 0a 6f a3 00 00 0a 06 07 6f a4 00 00 0a 17 73 96 00 00 0a 25 02 16 02 8e 69 6f a5 00 00 0a 6f a6 00 00 0a 06 28 5e 00 00 06 28 1a 01 00 06 2a}  //weight: 10, accuracy: High
        $x_2_2 = "BasedAntiVT.exe" ascii //weight: 2
        $x_2_3 = "m_f5f5698b1df04fb2a59b2feb2086e3c7" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_BU_2147840122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.BU!MTB"
        threat_id = "2147840122"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 04 00 00 8d ?? 00 00 01 13 0d 2b 0f 00 11 0b 11 0d 16 11 0c 6f ?? 00 00 0a 00 00 11 0a 11 0d 16 11 0d 8e 69 6f ?? 00 00 0a 25 13 0c 16 fe 02 13 0e 11 0e 2d d7}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBBM_2147841889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBBM!MTB"
        threat_id = "2147841889"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 46 06 07 28 ?? 00 00 0a 72 11 e6 01 70 02 18 8c ?? 00 00 01 07 28 ?? 00 00 0a 17 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 18 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a b4 9c 07 08 12 01 28 ?? 00 00 0a 2d ba}  //weight: 1, accuracy: Low
        $x_1_2 = "22A2C6EAF80DFC8FD8D8A2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_EH_2147843801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.EH!MTB"
        threat_id = "2147843801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 08 07 08 8e 69 5d 91 61 02 07 17 58 02 8e 69 5d 91 59}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ABD_2147843997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ABD!MTB"
        threat_id = "2147843997"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 0c 00 00 28 ?? ?? ?? 0a 06 03 6f ?? ?? ?? 0a 0b 07 8e 69 16 31 04 07 0c de 0e 14 0c de 0a 06 2c 06 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ABD_2147843997_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ABD!MTB"
        threat_id = "2147843997"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 0d 00 00 04 a2 11 12 18 28 ?? ?? ?? 0a 13 0f 12 0f 28 ?? ?? ?? 06 a2 11 12 19 7e 0d 00 00 04 a2 11 12 1a 7e 0e 00 00 04 13 10 12 10 28 ?? ?? ?? 06 a2 11 12 1b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_PSJZ_2147844438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PSJZ!MTB"
        threat_id = "2147844438"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 2b 00 00 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 77 00 00 70 15 16 28 ?? ?? ?? 0a 80 0b 00 00 04 7e 0b 00 00 04 17 9a 28 ?? ?? ?? 0a 72 e5 00 00 70 28 11 00 00 06 80 0c 00 00 04 20 e4 04 00 00 28 ?? ?? ?? 0a 7e 0b 00 00 04 17 9a 6f ?? ?? ?? 0a 26 7e 0c 00 00 04 28 12 00 00 06 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBDH_2147844946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBDH!MTB"
        threat_id = "2147844946"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 08 07 08 93 0d 09 20 ff 00 00 00 5f 06 25 17 58 0a 61 1e 62 09 1e 63 06 25 17 58 0a 61 d2 60 d1 9d 08 17 58 0c 08 07 8e 69 fe 04 2d d2}  //weight: 1, accuracy: High
        $x_1_2 = "6a8ab81f7b3a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_PSIU_2147844986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PSIU!MTB"
        threat_id = "2147844986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 20 98 3a 00 00 28 ?? ?? ?? 0a 00 28 0c 00 00 06 0a 20 98 3a 00 00 28 ?? ?? ?? 0a 00 06 72 33 00 00 70 72 67 00 00 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 20 98 3a 00 00 28 33 00 00 0a 00 02 07 28 14 00 00 06 00 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ABRM_2147845549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ABRM!MTB"
        threat_id = "2147845549"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetBytes" ascii //weight: 1
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_3_3 = "PNtI1fLt4Uo6sHbjOZ.h4cXQoprHHsXJ7n4FT" ascii //weight: 3
        $x_3_4 = "iW9w8DsHAomrjYpRwi.iihBjoh62YiGXsMgBR" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SPH_2147846054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SPH!MTB"
        threat_id = "2147846054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 73 40 00 00 0a 0c 73 41 00 00 0a 0d 08 09 28 ?? ?? ?? 0a 02 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 18 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 07 13 04 11 04 16 11 04 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ABTR_2147846301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ABTR!MTB"
        threat_id = "2147846301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f 00 08 20 00 04 00 00 58 28 ?? 00 00 2b 07 02 08 20 00 04 00 00 20 19 03 00 00 20 01 03 00 00 28 ?? 00 00 06 0d 1f 0c 13 0d}  //weight: 3, accuracy: Low
        $x_1_2 = "DeflateStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBCL_2147846347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBCL!MTB"
        threat_id = "2147846347"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 1b 2b 1c 2b 1d 2b 1e 2b 0a 2b 21 2b 22 02 6f 6f 00 00 0a 0b 19 2c f2}  //weight: 1, accuracy: High
        $x_1_2 = "9cade42e-5cc5-44ea-9892-da164d028a0e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBDZ_2147846388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBDZ!MTB"
        threat_id = "2147846388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 18 da 6b 28 ?? 00 00 0a 5a 28 ?? 00 00 0a 22 ?? ?? ?? 3f 58 6b 6c 28 ?? 00 00 0a b7 13 05 11 04 06 11 05 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 11 06 17 d6 13 06 11 06 11 07 31 ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_PSMS_2147847618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PSMS!MTB"
        threat_id = "2147847618"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 43 00 00 0a 26 72 1f 00 00 70 28 ?? ?? ?? 0a 00 28 06 00 00 06 6f ?? ?? ?? 0a 72 43 00 00 70 72 1f 00 00 70 6f ?? ?? ?? 0a 00 73 ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a 72 1f 00 00 70 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 26 72 1f 00 00 70 28 44 00 00 0a 00 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_PSMQ_2147848852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PSMQ!MTB"
        threat_id = "2147848852"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b 22 28 18 00 00 0a 02 6f 19 00 00 0a 0a 06 28 1a 00 00 0a 0b 08 20 c4 43 a6 58 5a 20 33 24 e4 8e 61 2b c1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NTE_2147849142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NTE!MTB"
        threat_id = "2147849142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 13 00 00 0a 0a 06 72 ?? 00 00 70 6f ?? 00 00 0a 0b 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 0c 08 07 28 ?? 00 00 0a 00 73 ?? 00 00 0a 0d}  //weight: 5, accuracy: Low
        $x_1_2 = "aufdemwegzurhaltestelle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_PSQT_2147849817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PSQT!MTB"
        threat_id = "2147849817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 89 01 00 0a 72 d4 01 00 70 6f a4 01 00 0a 73 a0 01 00 0a 25 6f 9b 01 00 0a 16 6a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBFP_2147850181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBFP!MTB"
        threat_id = "2147850181"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 11 06 2c 4c 07 06 28 ?? 00 00 0a 72 63 01 00 70 03 18 8c ?? 00 00 01 06 28 ?? 00 00 0a 17 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 18 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a b4 9c 00 06 11 05 12 00 28 ?? 00 00 0a 13 06 11 06 2d b4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AADS_2147850997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AADS!MTB"
        threat_id = "2147850997"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {26 11 05 8d ?? 00 00 01 0d 07 09 16 11 05 6f ?? 00 00 0a 26 16 13 06 2b 11 09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 32 e8}  //weight: 4, accuracy: Low
        $x_1_2 = "WindowsFormsApp1.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_PSSQ_2147851186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PSSQ!MTB"
        threat_id = "2147851186"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 28 ba 00 00 0a 03 28 ac 00 00 0a 6f af 00 00 0a 0a 2b 00 06 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AAHC_2147851569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AAHC!MTB"
        threat_id = "2147851569"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 01 00 00 70 0a 06 28 ?? 00 00 0a 0b 02 13 04 11 04 0c 07 28 ?? 00 00 0a 0d 00 09 6f ?? 00 00 0a 14 17 8d ?? 00 00 01 25 16 08 a2 6f ?? 00 00 0a 26 00 de 37}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AAHH_2147851623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AAHH!MTB"
        threat_id = "2147851623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 06 18 28 ?? 00 00 06 7e ?? 00 00 04 06 19 28 ?? 00 00 06 7e ?? 00 00 04 06 28 ?? 00 00 06 0d 7e ?? 00 00 04 09 03 16 03 8e 69 28 ?? 00 00 06 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBHK_2147852001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBHK!MTB"
        threat_id = "2147852001"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 6c 22 29 0d 0a 73 68 65 6c 6c 2e 52 75 6e 20 47 62 6b 6a 6b 73 6b 62 6e 6d 62 73 73 73}  //weight: 1, accuracy: High
        $x_1_2 = "dfdfdfgdjfidfgifgdhfgddfdf" wide //weight: 1
        $x_1_3 = "sS.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AAIP_2147852224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AAIP!MTB"
        threat_id = "2147852224"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 08 02 16 02 8e 69 28 ?? 00 00 06 7e ?? 00 00 04 08 28 ?? 00 00 06 de 0f 08 2c 0b 7e ?? 00 00 04 08 28 ?? 00 00 06 dc 7e ?? 00 00 04 07 28 ?? 00 00 06 0d de 5c}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NBI_2147852425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NBI!MTB"
        threat_id = "2147852425"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1a 8d 29 00 00 01 0b 06 07 16 1a 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 06 0c 06 16 73 ?? 00 00 0a 0d 08 8d ?? 00 00 01 13 04 16 28 ?? 00 00 06 39 ?? 00 00 00 26 20 ?? 00 00 00 38 ?? 00 00 00 09 11 04 16 08 28 ?? 00 00 06 26 38 ?? 00 00 00}  //weight: 5, accuracy: Low
        $x_1_2 = "SEEDCRACKER.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBHU_2147852879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBHU!MTB"
        threat_id = "2147852879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 00 00 40 41 16 19 16 73 2e 00 00 0a 6f ?? 00 00 0a 00 02 7b 2e 00 00 04 20 4a 01 00 00 20 4e 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "a270-55d3b0b8ce0f" ascii //weight: 1
        $x_1_3 = "CM_Links.Properties.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AAME_2147888526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AAME!MTB"
        threat_id = "2147888526"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 07 16 11 06 1f 0f 1f 10 28 ?? 00 00 0a 00 06 11 06 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 13 05 02 28 ?? 00 00 0a 13 04 28 ?? 00 00 0a 11 05 11 04 16 11 04 8e b7 6f ?? 00 00 0a 6f ?? 00 00 0a 0b de 10}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBIB_2147888673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBIB!MTB"
        threat_id = "2147888673"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 04 2b 19 09 06 16 11 04 6f ?? 00 00 0a 00 07 06 16 06 8e b7 6f ?? 00 00 0a 13 04 00 11 04 16 fe 02 13 06 11 06 2d dc}  //weight: 10, accuracy: Low
        $x_1_2 = "4d98-be9e-73e6f193401c" ascii //weight: 1
        $x_1_3 = "GetTypes" wide //weight: 1
        $x_1_4 = "MI.exe" ascii //weight: 1
        $x_1_5 = "Assembly" wide //weight: 1
        $x_1_6 = "CreateInstance" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SPL_2147889140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SPL!MTB"
        threat_id = "2147889140"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 1a 8d 38 00 00 01 0b 11 04 11 04 6f ?? ?? ?? 0a 1b 6a da 6f ?? ?? ?? 0a 11 04 07 16 1a 6f ?? ?? ?? 0a 26 07 16 28 ?? ?? ?? 0a 0c 11 04 16 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBEN_2147889314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBEN!MTB"
        threat_id = "2147889314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0d 1e 8d ?? 00 00 01 0a 09 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 11 04 16 06 16 1e 28 ?? 00 00 0a 00 07 06 6f ?? 00 00 0a 00 07 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ABAA_2147890137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ABAA!MTB"
        threat_id = "2147890137"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0c 01 00 fe 0c 02 00 8f ?? 00 00 01 25 47 fe 0c 01 00 fe 0c 07 00 91 fe 0c 00 00 20 ?? 00 00 00 58 4a 61 d2 61 d2 52 20 ?? 00 00 00 fe 0e 0a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 fe 0c 05 00 fe 0c 00 00 20 08 00 00 00 58 fe 0c 01 00 8e 69 fe 17 20 0b 00 00 00 fe 0e 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {fe 0c 00 00 fe 09 00 00 fe 0c 00 00 4a 61 58 fe 0e 00 00 20 07 00 00 00 fe 0e 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBIO_2147891281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBIO!MTB"
        threat_id = "2147891281"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 15 a2 09 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 56 00 00 00 0d 00 00 00 16 00 00 00 41 00 00 00 35 00 00 00 92}  //weight: 1, accuracy: High
        $x_1_2 = "$b55d4eb0-cd6a-4c25-8433-a8b15b906830" ascii //weight: 1
        $x_1_3 = "WindowsApplication2.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NBD_2147891419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NBD!MTB"
        threat_id = "2147891419"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 01 00 fe 0c 00 00 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a fe ?? ?? 00 20 ?? 00 00 00 6f ?? 00 00 0a fe ?? ?? 00 20 ?? 00 00 00 6f ?? 00 00 0a fe ?? ?? 00 6f ?? 00 00 0a fe ?? ?? 00 fe ?? ?? 00 28 ?? 00 00 0a fe ?? ?? 00 fe ?? ?? 00 fe ?? ?? 00 20 ?? 00 00 00 fe ?? ?? 00 8e 69 6f ?? 00 00 0a fe ?? ?? 00 28 ?? 00 00 0a fe ?? ?? 00 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "tmpC394.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBJC_2147891594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBJC!MTB"
        threat_id = "2147891594"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 72 ff 01 00 70 16 14 28 ?? 00 00 0a 26 00 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "9b-270ae327a12" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_KA_2147891724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.KA!MTB"
        threat_id = "2147891724"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 42 2b 1f 2b 41 2b 42 2b 43 08 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c 16 2d 0d 08 17 25 2c 05 58 0c 08 06 8e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_GP_2147891924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.GP!MTB"
        threat_id = "2147891924"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {fe 0e 2d 00 fe 0c 29 00 fe 0c 29 00 1b 62 61 fe 0e 29 00 fe 0c 29 00 fe 0c 2a 00 58 fe 0e 29 00 fe 0c 29 00 fe 0c 29 00 1f 15 62 61 fe 0e 29 00 fe 0c 29 00 fe 0c 2c 00 58 fe 0e 29 00 fe 0c 29 00 fe 0c 29 00 19 64 61 fe 0e 29 00 fe 0c 29 00 fe 0c 2d 00 58 fe 0e 29 00 fe 0c 28 00 1f 15 62 fe 0c 28 00 58 fe 0c 2a 00 61 fe 0c 29 00 59}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBJI_2147892085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBJI!MTB"
        threat_id = "2147892085"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 03 8e 69 da 04 8e 69 d6 17 da 17 d6 8d ?? 00 00 01 0b 02 16 07 16 08 28 ?? 00 00 0a 00 04 16 07 08 04 8e 69}  //weight: 1, accuracy: Low
        $x_1_2 = "471b-96f8-aa4ba8af9efb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBJK_2147892086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBJK!MTB"
        threat_id = "2147892086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 00 67 00 4e 00 4b 00 5a 00 34 00 49 00 53 00 38 00 4d 00 61 00 4e 00 62 00 70 00 4f 00 65 00 53 00 55 00 75 00 64 00 73 00 53 00 46 00 57 00 71 00 6a 00 6e 00 45 00 6c 00 62}  //weight: 1, accuracy: High
        $x_1_2 = {66 00 65 00 4f 00 34 00 57 00 46 00 59 00 55 00 52 00 76 00 6d 00 6b 00 74 00 68 00 38 00 74 00 6e 00 62 00 54 00 61 00 52 00 6a 00 4a 00 4f 00 61 00 36 00 4a 00 59}  //weight: 1, accuracy: High
        $x_1_3 = {20 b8 88 00 00 28}  //weight: 1, accuracy: High
        $x_1_4 = "sss.Resources" ascii //weight: 1
        $x_1_5 = "MD5CryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ASDX_2147893815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ASDX!MTB"
        threat_id = "2147893815"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 d4 b3 d8 d9 58 5f 58 59 02 73 ?? 00 00 0a 0a 73 ?? 00 00 0a 0b 28 ?? 00 00 0a 38 ?? ?? 00 00 03 28 ?? 00 00 0a 04 6f ?? 00 00 0a 73 ?? 00 00 0a 0d 08 09 1f 20 6f ?? 00 00 0a 38}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SPQI_2147895322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SPQI!MTB"
        threat_id = "2147895322"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 08 28 ?? ?? ?? 06 58 0c 08 02 8e 69 3f e0 ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ASFO_2147895490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ASFO!MTB"
        threat_id = "2147895490"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8e 69 fe 04 2c 38 2b 76 08 07 08 93 0d 09 20 ff 00 00 00 5f 06 25 17 58 0a 61 1e 62 09 1e 63 06 25 17 58 0a 61 d2 60 d1 9d 18 2b 99 08 17 58 16 3a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SPQN_2147895919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SPQN!MTB"
        threat_id = "2147895919"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {07 08 07 08 91 02 08 1f 10 5d 91 61 9c 08 17 58 0c 08 09 31 eb}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SLT_2147896141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SLT!MTB"
        threat_id = "2147896141"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 0a 16 2b 01 16 45 04 00 00 00 02 00 00 00 07 00 00 00 0e 00 00 00 13 00 00 00 2b 26 03 0b 17 2b e4 06 8e 69 0c 18 2b dd 16 0d 19 2b d8 2b 17 07 09 07 09 91 06 09 08 5d 91 28 ?? ?? ?? 06 9c 1a 2b c3 09 17 58 0d 09 07 8e 69 32 e3 07 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_PTBW_2147896541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PTBW!MTB"
        threat_id = "2147896541"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 06 00 00 0a 03 50 6f 04 00 00 0a 0a 06 28 ?? 00 00 0a 0b 07 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_PTCJ_2147897095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PTCJ!MTB"
        threat_id = "2147897095"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 20 00 00 06 6f 4e 00 00 0a 02 72 fb 00 00 70 6f 45 00 00 0a 02 72 fb 00 00 70 6f 4f 00 00 0a 02 16 6f 50 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_PTDM_2147898328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PTDM!MTB"
        threat_id = "2147898328"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 6f 10 00 00 0a 69 8d 14 00 00 01 0a 08 06 16 06 8e 69 6f 11 00 00 0a 26 de 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_PTEA_2147899013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PTEA!MTB"
        threat_id = "2147899013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 62 03 00 70 28 ?? 00 00 0a 26 02 28 ?? 01 00 0a 0a 28 ?? 01 00 0a 06 16 06 8e 69 6f 68 01 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_DQ_2147899391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.DQ!MTB"
        threat_id = "2147899391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 03 07 03 6f ?? ?? ?? 0a 5d 17 58 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 59 0c 06 08 28 ?? ?? ?? 0a 0d 12 03 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 00 07 17 58 0b 07 02 6f ?? ?? ?? 0a fe 02 16 fe 01 13 04 11 04 2d b0}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "RSM_Decrypt" ascii //weight: 1
        $x_1_4 = "VigenereDecrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ABB_2147900257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ABB!MTB"
        threat_id = "2147900257"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0d 00 00 07 08 16 20 00 10 00 00 6f ?? 00 00 0a 13 04 11 04 16 fe 02 13 05 11 05 2c 0b 09 08 16 11 04 6f ?? 00 00 0a 00 00 11 04 16 fe 02 13 05 11 05 2d cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_PTFM_2147900623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PTFM!MTB"
        threat_id = "2147900623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 c5 00 00 70 6f 04 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SPDU_2147901614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SPDU!MTB"
        threat_id = "2147901614"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 0b 7e 0e 00 00 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 2c 2d 28 ?? ?? ?? 06 13 07 06 11 07 16 28 ?? ?? ?? 0a 16 2e 1a 11 07 0a 72 8d 05 00 70 7e 21 00 00 04 11 07 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 26 de 0f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_CWAA_2147902011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.CWAA!MTB"
        threat_id = "2147902011"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0c 2b 2d 02 08 6f ?? 00 00 0a 03 08 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 0d 07 72 ?? ?? 00 70 09 28 ?? 00 00 0a 6f ?? 00 00 0a 26 08 17 58 0c 08 02 6f ?? 00 00 0a 32 ca}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBFT_2147902316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBFT!MTB"
        threat_id = "2147902316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 69 c2 84 64 54 54 60 54 54 54 54 58 54 54 54 54 42 42 4b 54 54 5f 7a 54 54 54 54 54 54 54 54 54 64 54 54 54 54 54 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_GPA_2147902464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.GPA!MTB"
        threat_id = "2147902464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 84 95 11 ?? 08 84 95 d7 6e 20 ?? ?? 00 00 6a 5f b7 95 61 86 9c 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBFU_2147902476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBFU!MTB"
        threat_id = "2147902476"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TVqQ==M====E====//8==Lg=========Q===============================================g=====4fug4=t=nNI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_GPB_2147902604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.GPB!MTB"
        threat_id = "2147902604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 02 8e 69 17 da 0c 02 08 91 ?? ?? 61 0d 02 8e 69 17 d6}  //weight: 5, accuracy: Low
        $x_5_2 = {91 09 61 07 11 ?? 91 61 b4 9c 11}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_GPC_2147902893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.GPC!MTB"
        threat_id = "2147902893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sk-krona.fun" ascii //weight: 1
        $x_1_2 = {00 52 65 73 69 7a 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {52 65 76 65 72 73 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBFV_2147902908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBFV!MTB"
        threat_id = "2147902908"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vhZqXQFEEnmGticLIbhGKiL1lR83HNY9" wide //weight: 1
        $x_1_2 = "RC2MD5Decrypt" ascii //weight: 1
        $x_1_3 = "hbQ4ox6YeZt50KPF0BaN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ND_2147903522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ND!MTB"
        threat_id = "2147903522"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 1c}  //weight: 5, accuracy: Low
        $x_5_2 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 1b}  //weight: 5, accuracy: Low
        $x_5_3 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 1f}  //weight: 5, accuracy: Low
        $x_5_4 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 1e}  //weight: 5, accuracy: Low
        $x_5_5 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 18}  //weight: 5, accuracy: Low
        $x_5_6 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 19}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Bladabindi_NE_2147903524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NE!MTB"
        threat_id = "2147903524"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 16}  //weight: 5, accuracy: Low
        $x_5_2 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 17}  //weight: 5, accuracy: Low
        $x_5_3 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 1a}  //weight: 5, accuracy: Low
        $x_5_4 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 1d}  //weight: 5, accuracy: Low
        $x_5_5 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 22}  //weight: 5, accuracy: Low
        $x_5_6 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 30}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Bladabindi_NE_2147903524_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NE!MTB"
        threat_id = "2147903524"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e ?? 00 00 04 0e 06 17 59 e0 95 58 0e 05 28 7b 02 00 06 58 54}  //weight: 10, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "RegistryKeyPermissionCheck" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
        $x_1_5 = "ReadProcessMemory" ascii //weight: 1
        $x_1_6 = "System.Security.Cryptography" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_PTJN_2147903868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PTJN!MTB"
        threat_id = "2147903868"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b7 16 6f 33 00 00 0a 13 0b 06 08 16 11 0b 6f 15 00 00 0a 06 6f 18 00 00 0a 07 33 22}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NB_2147904134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NB!MTB"
        threat_id = "2147904134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {20 29 27 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 02 18 16 8d 01 00 00 01 28 ?? 00 00 0a 0a 06 2a}  //weight: 3, accuracy: Low
        $x_2_2 = {20 66 08 00 00 28 ?? 00 00 0a 20 45 15 00 00 72 bb 02 00 70 28 ?? 00 00 06 28 ?? 00 00 0a 0a 06 2a}  //weight: 2, accuracy: Low
        $x_1_3 = "cxzcxzxcz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NB_2147904134_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NB!MTB"
        threat_id = "2147904134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {07 6f 96 00 00 0a 28 a9 01 00 06 02 7b c3 01 00 04 6f a9 01 00 0a 13 09 11 09 39 dd 00 00 00 07 6f 96 00 00 0a 02 7b c3 01 00 04 28 aa 01 00 06 13 04 02 7b c1 01 00 04 13 06 11 06 14 fe 01 16 fe 01 13 09 11 09 2c 2a}  //weight: 3, accuracy: High
        $x_2_2 = {8d 05 00 00 01 13 07 11 07 16 16 8c 4e 00 00 01 a2 00 11 07 14 28 1a 01 00 0a 74 18 00 00 1b 6f f4 01 00 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NB_2147904134_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NB!MTB"
        threat_id = "2147904134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 2f 00 00 0a 0b 11 06 1f 78 91 13 05 38 50 ff ff ff 06 17 58 0a 1f 6b 0d 20 ef 00 00 00 0c 20 cd 02 00 00 08 09 19 5a 59 30 12 11 07 1f 18 93 20 b4 86 00 00 59 13 05 38 25 ff ff ff 16 2b f6 11 07 20 a6 00 00 00 93 20 fe 9c 00 00 59 13 05 38 0d ff ff ff 07 74 09 00 00 01 2a 11 07 1f 71 93 20 7f 4e 00 00 59 13 05}  //weight: 5, accuracy: High
        $x_1_2 = "BPNIGLWZHAQJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_GPD_2147904471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.GPD!MTB"
        threat_id = "2147904471"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "M#g#A#u#A#G#4#A#b#w#A#t#A#G#k#A#c#A#A#u#A#G#I#A#a#Q#B#6#A#A#A" ascii //weight: 5
        $x_5_2 = "T#V#q#Q#A#A#M#A#A#A#A#E#A#A#A#A#" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_RDB_2147905291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.RDB!MTB"
        threat_id = "2147905291"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 11 04 17 28 9a 00 00 0a 13 0b 08 11 07 06 11 0b 28 9b 00 00 0a 11 09 61}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ASGE_2147905952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ASGE!MTB"
        threat_id = "2147905952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 17 11 17 2c 2e 11 06 11 0e 11 0d 17 28 ?? 00 00 0a 17 11 09 61 28 ?? 00 00 0a 28}  //weight: 1, accuracy: Low
        $x_1_2 = {13 17 11 17 2c 2a 02 11 04 17 28 ?? 00 00 0a 13 0b 08 11 07 06 11 0b 28 ?? 00 00 0a 11 09 61 28 ?? 00 00 0a 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_PSTI_2147906120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PSTI!MTB"
        threat_id = "2147906120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b 09 28 b8 9b 3c 3c 14 16 9a 26 16 2d f9 28 3b 04 00 06 28 25 01 00 06 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ABL_2147906608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ABL!MTB"
        threat_id = "2147906608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 09 07 91 06 07 06 08 8c 40 00 00 01 80 01 00 00 04 8e 69 5d 91 07 08 d6 20 68 d6 5d 31 80 10 00 00 04 06 8e 69 d6 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_HNA_2147907739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.HNA!MTB"
        threat_id = "2147907739"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 00 73 65 74 5f 46 69 6c 65 4e 61 6d 65 00 73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 00 73 65 74 5f 56 65 72 62 00 73 65 74 5f 41 72 67 75 6d 65 6e 74 73 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 4d 65 6d 6f 72 79 53 74 72 65 61 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 47 65 74 46 6f 72 65 67 72 6f 75 6e 64 57 69 6e 64 6f 77 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 47 65 74 57 69 6e 64 6f 77 54 65 78 74 41 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 47 65 74 57 69 6e 64 6f 77 54 65 78 74 4c 65 6e 67 74 68 41 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 47 65 74 4d 6f 64 75 6c 65 73 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 53 74 72 52 65 76 65 72 73 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NH_2147910551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NH!MTB"
        threat_id = "2147910551"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 61 b7 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 06 11 04 6f ?? 00 00 0a 26 07}  //weight: 5, accuracy: Low
        $x_1_2 = "textfile.txt" ascii //weight: 1
        $x_1_3 = "Microsoft\\svchost.exe" ascii //weight: 1
        $x_1_4 = "cmd.exe /k ping 0 & del" ascii //weight: 1
        $x_1_5 = "root\\SecurityCenter" ascii //weight: 1
        $x_1_6 = "SELECT * FROM FirewallProduct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_ASL_2147910568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.ASL!MTB"
        threat_id = "2147910568"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 04 11 05 8f ?? 00 00 01 25 71 ?? 00 00 01 11 05 0e 04 58 20 ff 00 00 00 5f d2 61 d2 81 ?? 00 00 01 11 05 17 58 13 05 11 05 04 32}  //weight: 4, accuracy: Low
        $x_1_2 = "c3R1YnN0dWI=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NK_2147915267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NK!MTB"
        threat_id = "2147915267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0b 08 17 58 0c 08 06 8e 69 17 59 fe 02 16 fe 01 13 04 11 04 2d dc}  //weight: 5, accuracy: High
        $x_1_2 = "Nero lait\\obj\\Debug\\Nero lait.pdb" ascii //weight: 1
        $x_1_3 = "StrReverse" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NM_2147915269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NM!MTB"
        threat_id = "2147915269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 11 4b 11 05 4b 61 ?? ?? ?? ?? 00 5f 16 fe 01}  //weight: 5, accuracy: Low
        $x_5_2 = {13 0f 11 0f 1f 0c 64 11 0f 61 ?? ?? 0f 00 00 5f 13 0c 11 06 11 0c}  //weight: 5, accuracy: Low
        $x_1_3 = "eb3c99ae-4ab0-4043-9bd0-2fbcbed02fdd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NP_2147917944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NP!MTB"
        threat_id = "2147917944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "i_Shitted_My_Self.exe" ascii //weight: 2
        $x_2_2 = "sKiDtOoLs_WhY_u_LoOkIg_HeRe" wide //weight: 2
        $x_1_3 = "ShopChop#6936" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NP_2147917944_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NP!MTB"
        threat_id = "2147917944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://167.71.14.135" ascii //weight: 2
        $x_1_2 = "Add-MpPreference -ExclusionProcess \"svchost.exe\"" ascii //weight: 1
        $x_1_3 = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii //weight: 1
        $x_1_4 = "AppData\\Roaming\\Microsoft\\Windows';Add-MpPreference -ExclusionPath 'C:\\Users" ascii //weight: 1
        $x_1_5 = "Microsoft\\Windows\\Windows.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NT_2147918732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NT!MTB"
        threat_id = "2147918732"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "7105fc5d-9d29-4e73-ac81-2da1962bb909" ascii //weight: 2
        $x_2_2 = "FromBase64String" ascii //weight: 2
        $x_1_3 = "audacity_win" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NQ_2147920138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NQ!MTB"
        threat_id = "2147920138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://167.71.14.135" ascii //weight: 2
        $x_1_2 = "Add-MpPreference -ExclusionProcess" ascii //weight: 1
        $x_1_3 = "powershell.exe" ascii //weight: 1
        $x_1_4 = "Microsoft\\Windows\\Windows.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_NS_2147920139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.NS!MTB"
        threat_id = "2147920139"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e 44 03 00 04 0e 06 17 59 e0 95 58 0e 05 28 3f 05 00 06 58 54 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBXS_2147920579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBXS!MTB"
        threat_id = "2147920579"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {36 42 30 77 36 61 00 63 48 38 49 58 63 77 51 59 34 50 65 68 32 71 70 41 6e 00 52 32 6d 49 61}  //weight: 3, accuracy: High
        $x_2_2 = {74 69 6f 6e 00 76 69 64 65 6f 73 6f 66 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_MBXV_2147924088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.MBXV!MTB"
        threat_id = "2147924088"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {52 00 65 00 70 00 6c 00 61 00 63 00 65 00 00 03 26 00 00 03 41 00 00 11 43 00 75 00 75 00 67 00 6f 00 64 00 6e 00 61 00 00 13 43 00 72 00 72 00 46 00 71}  //weight: 2, accuracy: High
        $x_1_2 = "sdfsdfs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_KAAG_2147924329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.KAAG!MTB"
        threat_id = "2147924329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 0d 06 09 03 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 25 26 07 09 07 8e 69 5d 91 61 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AYA_2147926817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AYA!MTB"
        threat_id = "2147926817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$1F8B2271-7303-4F2F-8B4B-556A5FCB3C86" ascii //weight: 2
        $x_1_2 = "MBR Overwritten, Victim rebooted." wide //weight: 1
        $x_1_3 = "schtasks /create /sc minute /mo 1 /tn" wide //weight: 1
        $x_1_4 = "Select * From AntiVirusProduct" wide //weight: 1
        $x_1_5 = "WhyYouReverseMe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AYB_2147927993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AYB!MTB"
        threat_id = "2147927993"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "$18517ba6-baa9-4ff4-a669-01fbf31b53a1" ascii //weight: 3
        $x_1_2 = "XClient.g.resources" ascii //weight: 1
        $x_1_3 = "XClient.exe" wide //weight: 1
        $x_1_4 = "is tampered." wide //weight: 1
        $x_1_5 = "Debugger Detected" wide //weight: 1
        $x_1_6 = "XLogger" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_EABQ_2147932236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.EABQ!MTB"
        threat_id = "2147932236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 06 23 00 00 00 00 00 00 3a 40 07 6f a0 00 00 0a 5a 23 00 00 00 00 00 40 50 40 58 28 a1 00 00 0a 28 a2 00 00 0a 28 a3 00 00 0a 0d 12 03 28 a4 00 00 0a 28 60 00 00 0a 0a 00 08 17 58 0c 08 1b fe 04 13 04 11 04 3a b5 ff ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_EAU_2147934434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.EAU!MTB"
        threat_id = "2147934434"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 08 9a 6f 5a 00 00 0a 02 16 28 33 00 00 0a 16 33 04 06 08 9a 2a 08 17 d6 0c 08 09 31 e2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AXMA_2147935099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AXMA!MTB"
        threat_id = "2147935099"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {1a 2c 32 00 2b 14 2b 19 2b 1e 1e 2d 06 26 16 2d 04 de 22 2b 1a 19 2c ec 2b f4 28 ?? 00 00 06 2b e5 28 ?? 00 00 2b 2b e0 28 ?? 00 00 2b 2b db 0a 2b e3 26 de cb}  //weight: 4, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_AYC_2147935295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.AYC!MTB"
        threat_id = "2147935295"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "crypter0.My.Resources" ascii //weight: 2
        $x_2_2 = "$5a2143b9-b866-4334-bb69-fd58643e4771" ascii //weight: 2
        $x_1_3 = "ExtractAndRunExe" ascii //weight: 1
        $x_1_4 = "DecryptFile" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "WriteAllBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SWA_2147935622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SWA!MTB"
        threat_id = "2147935622"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 16 11 04 11 07 11 06 28 1f 00 00 0a 11 07 11 06 58 13 07 07 11 05 16 20 00 01 00 00 6f 20 00 00 0a 25 13 06 16 30 d7 20 61 ff 6f 00 13 08 06 13 0d 16 13 0e 2b 1a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_PKMZ_2147936651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.PKMZ!MTB"
        threat_id = "2147936651"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {00 72 9d 00 00 70 0c 72 bb 00 00 70 0d 72 d3 00 00 70 13 04 18 13 05 72 dd 00 00 70 13 06 20 00 01 00 00 0a 28 ?? 00 00 0a 11 06 6f ?? 00 00 0a 13 07 28 ?? 00 00 0a 09 6f ?? 00 00 0a 13 08 02 28 ?? 00 00 0a 13 09 08 11 08 11 04 11 05 73 0b 00 00 0a 13 0a 11 0a 06 1e 5b 6f ?? 00 00 0a 13 0b 73 0d 00 00 0a 13 0c 11 0c 17 6f ?? 00 00 0a 00 11 0c 11 0b 11 07 6f ?? 00 00 0a 13 0d}  //weight: 4, accuracy: Low
        $x_2_2 = {de 00 00 08 28 ?? 00 00 0a 0d 09 14 72 79 00 00 70 16 8d 03 00 00 01 14 14 14 28 ?? 00 00 0a 14 72 8f 00 00 70 18 8d 03 00 00 01 13 0c 11 0c 16 14 a2 00 11 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_GPPA_2147938484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.GPPA!MTB"
        threat_id = "2147938484"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7a 06 14 6f ?? 00 00 0a 75 ?? 00 00 01 0b 07 14 28 ?? 00 00 0a 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_GPPB_2147938485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.GPPB!MTB"
        threat_id = "2147938485"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "R///e///////g/A//////s/m/./e////x/////e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SLWA_2147941055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SLWA!MTB"
        threat_id = "2147941055"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 11 05 72 ?? 01 00 70 6f 30 00 00 0a 11 05 72 ?? 01 00 70 6f 31 00 00 0a 11 05 17 6f 32 00 00 0a 11 05 17}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_SLAW_2147941504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.SLAW!MTB"
        threat_id = "2147941504"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {12 02 2b 27 72 dd 00 00 70 2b 27 80 17 00 00 04 7e 17 00 00 04 14 2b 21 2c 0c 7e 17 00 00 04 2b 1f 80 18 00 00 04 de 2f 07 2b d5 28 d8 00 00 0a 2b d2 28 d9 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bladabindi_GRR_2147946029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladabindi.GRR!MTB"
        threat_id = "2147946029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 59 01 00 70 6f 2a 00 00 0a 0a 06 72 5f 01 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

