rule Trojan_MSIL_AveMariaRAT_RPT_2147817794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.RPT!MTB"
        threat_id = "2147817794"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 00 6c 00 75 00 65 00 63 00 6f 00 76 00 65 00 72 00 74 00 72 00 61 00 64 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 [0-32] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = "dll.txt" wide //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "Convert" ascii //weight: 1
        $x_1_6 = "GetResponseStream" ascii //weight: 1
        $x_1_7 = "WebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_NT_2147818339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.NT!MTB"
        threat_id = "2147818339"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d5 02 28 09 0f 00 00 00 d0 00 20 00 06 00 00 01 00 00 00 63 00 00 00 65 00 00 00 b0 00 00 00 0a 01 00 00 20 00 00 00 97}  //weight: 1, accuracy: High
        $x_1_2 = "hPfdsfhdsdrodscess" ascii //weight: 1
        $x_1_3 = "lpBasfsdsdfeddfhsAddress" ascii //weight: 1
        $x_1_4 = "lpBfdsdhsdsdsfuffer" ascii //weight: 1
        $x_1_5 = "Copooopooopopooopppppqpooopoo" ascii //weight: 1
        $x_1_6 = "Atsssssssssssssssssssss" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_NT_2147818339_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.NT!MTB"
        threat_id = "2147818339"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 ed 06 c7 06 c7 06 c7 06 c7 06 c7 06 ba 06 ec 06 fb 06 ed 06 ba 06 c7 06 fa 06 c7 06 f4 06 d4 06 cf 06 e8 06 ed}  //weight: 1, accuracy: High
        $x_1_2 = {c7 06 c7 06 cd 06 d0 06 ee 06 e9 06 da 06 c8 06 ff 06 fc 06 e7 06 c7 06 f4 06 d3 06 c9 06 c7 06 c7 06 c7 06 d1 06 c9 06 ee 06 f5 06 da 06 c9 06 d8 06 cb 06 d0 06 d8 06 d7}  //weight: 1, accuracy: High
        $x_1_3 = {ca 06 cb 06 c7 06 d2 06 ed 06 c7 06 00 07 c7 06 c9 06 ba 06 c7 06 d3 06 c7 06 c7 06 fb 06 c7 06 ca 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7}  //weight: 1, accuracy: High
        $x_1_4 = "92b636e7-7f80-4a35-bf59-089e30b0dd72" ascii //weight: 1
        $x_1_5 = "CPT185" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_NUE_2147818568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.NUE!MTB"
        threat_id = "2147818568"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 02 20 00 22 00 00 04 28 ?? ?? ?? 06 03 04 17 58 20 00 22 00 00 5d 91 28}  //weight: 1, accuracy: Low
        $x_1_2 = "Voroni.Properties.Resources.r" ascii //weight: 1
        $x_1_3 = "38F4WP9E4HH858FASCJSB5" ascii //weight: 1
        $x_1_4 = "Rostisa" ascii //weight: 1
        $x_1_5 = "GetMethods" ascii //weight: 1
        $x_1_6 = "todo.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_NHG_2147818583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.NHG!MTB"
        threat_id = "2147818583"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jkhjfjhjhgkasdnfihsiajgo'sdfhjjfhljiup" ascii //weight: 1
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "System.Reflection.Assembly" ascii //weight: 1
        $x_1_4 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_5 = "poldata5.UpdateSnooze" ascii //weight: 1
        $x_1_6 = "ldata5.FetchMemoForReminder" ascii //weight: 1
        $x_1_7 = "[poldata5].[DeleteExistingReminder]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_NYD_2147826836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.NYD!MTB"
        threat_id = "2147826836"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 00 65 00 73 00 6f 00 00 07 75 00 72 00 63 00 00 05 65 00 73}  //weight: 1, accuracy: High
        $x_1_2 = "Mandlopgfcjdgf" wide //weight: 1
        $x_1_3 = "zzMzeztzhzozzzdz0zzzzz" wide //weight: 1
        $x_1_4 = "GetManifestResourceNames" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_NYJ_2147827607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.NYJ!MTB"
        threat_id = "2147827607"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 54 00 65 00 66 00 73 00 64 00 64 00 64 00 64 00 64 00 6d 00 70 00 00 41 43 00 3a 00 5c 00 4e 00 65 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 77 00 54 00 65 00 6d 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_NYJ_2147827607_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.NYJ!MTB"
        threat_id = "2147827607"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 72 00 65 00 73 00 00 09 6f 00 75 00 72 00 63 00 00 05 65 00 73 00 00 2f 53 00 53 00 4d 00 53}  //weight: 1, accuracy: High
        $x_1_2 = "SSMSSSeSStShSoSSSdSS0SS" ascii //weight: 1
        $x_1_3 = "DeatH" ascii //weight: 1
        $x_1_4 = "GetManifestResourceNames" ascii //weight: 1
        $x_1_5 = "Coisdhvpsduyps98yvhajn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_NYE_2147828035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.NYE!MTB"
        threat_id = "2147828035"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 00 65 00 73 00 00 09 6f 00 75 00 72 00 63 00 00 05 65 00 73}  //weight: 1, accuracy: High
        $x_1_2 = "GGMGGeGGGtGGGhGoGGGGdG0GG" wide //weight: 1
        $x_1_3 = "CoCAc" wide //weight: 1
        $x_1_4 = "KANFKAJcmlnk" wide //weight: 1
        $x_1_5 = "GetManifestResourceNames" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_NYG_2147828357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.NYG!MTB"
        threat_id = "2147828357"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 00 65 00 73 00 00 09 6f 00 75 00 72 00 63 00 00 05 65 00 73 00 00 35 48 00 48}  //weight: 1, accuracy: High
        $x_1_2 = "HHMHeHHHtHHHhHHHoHHHdHH0HH" wide //weight: 1
        $x_1_3 = "nnmiiut" wide //weight: 1
        $x_1_4 = "SayBulletLine" wide //weight: 1
        $x_1_5 = "MFIA" wide //weight: 1
        $x_1_6 = "GetManifestResourceNames" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_NYH_2147828779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.NYH!MTB"
        threat_id = "2147828779"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 72 00 65 00 73 00 00 09 6f 00 75 00 72 00 63 00 00 05 65 00 73}  //weight: 1, accuracy: High
        $x_1_2 = "KKMKKeKKtKKhKKoKKdKK0KK" wide //weight: 1
        $x_1_3 = "ARABE" wide //weight: 1
        $x_1_4 = "UIdijsid7" wide //weight: 1
        $x_1_5 = "GetManifestResourceNames" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_NYK_2147829299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.NYK!MTB"
        threat_id = "2147829299"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\somedirectory" ascii //weight: 1
        $x_1_2 = "C:\\Tefsdssddddmp" ascii //weight: 1
        $x_1_3 = "C:\\NeddssssssssssssssddddddddddddddddddddwTemp" ascii //weight: 1
        $x_1_4 = "fjffcffkfhgj" ascii //weight: 1
        $x_1_5 = "gddfdshsfdgh" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_NYS_2147829627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.NYS!MTB"
        threat_id = "2147829627"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\soggsssssgggggggmedirectory" ascii //weight: 1
        $x_1_2 = "C:\\NeddssssssssssssssddddddddddddddddddddwTemp" ascii //weight: 1
        $x_1_3 = "fjffcfsfkfhgj" ascii //weight: 1
        $x_1_4 = "gddfdshsfdgh" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "hkfsffhhcf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_NYI_2147829748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.NYI!MTB"
        threat_id = "2147829748"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RRRRMRRRReRRRRtRRRRhRRRRoRRRRdRRRR0RRRR" ascii //weight: 1
        $x_1_2 = {2e 00 72 00 65 00 73 00 00 09 6f 00 75 00 72 00 63 00 00 05 65 00 73 00 00 4f 52 00 52}  //weight: 1, accuracy: High
        $x_1_3 = "SnipeR" ascii //weight: 1
        $x_1_4 = "nnq8mdaoiusnuad678" ascii //weight: 1
        $x_1_5 = "GetManifestResourceNames" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_NYT_2147829749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.NYT!MTB"
        threat_id = "2147829749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\soggsssssgggggggmedirectory" ascii //weight: 1
        $x_1_2 = "C:\\somfffffffffffedirectory" ascii //weight: 1
        $x_1_3 = "Ssucggsshhhgdddddddsddddfccggdfsdefss" ascii //weight: 1
        $x_1_4 = "fjffcfsfkfhgj" ascii //weight: 1
        $x_1_5 = "gddfdshsfdgh" ascii //weight: 1
        $x_1_6 = "hjffscffkhj" ascii //weight: 1
        $x_1_7 = "FromBase64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_A_2147838649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.A!MTB"
        threat_id = "2147838649"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MLNLOLSRTRWVYXZX[Z\\X]X" wide //weight: 2
        $x_2_2 = "XaXbXcXdXeXfXgXkjljmjnjojpjqj" wide //weight: 2
        $x_2_3 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 2
        $x_2_4 = "costura.costura.dll.compressed" ascii //weight: 2
        $x_2_5 = "costura.newtonsoft.json.dll.compressed" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_B_2147839194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.B!MTB"
        threat_id = "2147839194"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 1b 1a 9a 18 8d ?? 00 00 01 25 16 11 05 a2 25 17 16 16 02 17 8d ?? 00 00 01 25 16 11 05 a2 14 28}  //weight: 2, accuracy: Low
        $x_1_2 = "GetResponse" ascii //weight: 1
        $x_1_3 = "set_KeepAlive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_D_2147844642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.D!MTB"
        threat_id = "2147844642"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 08 04 8e 69 5d 04 08 04 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 0a 04 08 1d 58 1c 59 04 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 08 17 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_E_2147845482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.E!MTB"
        threat_id = "2147845482"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CASLLLLLLL" ascii //weight: 2
        $x_2_2 = "MOANMZAAAAAAAR" ascii //weight: 2
        $x_2_3 = "InstallRegistry" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_G_2147846853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.G!MTB"
        threat_id = "2147846853"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 11 05 02 11 05 91 11 04 61 08 07 91 61 b4 9c 07 03 6f}  //weight: 2, accuracy: High
        $x_2_2 = "dasdasd" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_H_2147847286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.H!MTB"
        threat_id = "2147847286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 06 11 07 6f ?? 00 00 0a 13 08 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 11 07 17 58 13 07 11 07 07 6f 30 00 00 0a 32 ?? 11 06 17 58 13 06 11 06 07 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "GetExportedTypes" ascii //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_MAAY_2147848744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.MAAY!MTB"
        threat_id = "2147848744"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$acec886d-89a8-4153-9706-c2bdec389144" ascii //weight: 10
        $x_10_2 = "$7f84feb1-d02b-41b7-a951-b990c00d9c93" ascii //weight: 10
        $x_1_3 = "Confuser.Core 1.6" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_AveMariaRAT_I_2147849706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.I!MTB"
        threat_id = "2147849706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 d5 a2 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 b1 00 00 00 1e 00 00 00 8a 02 00 00 62 07}  //weight: 2, accuracy: High
        $x_2_2 = "QuanLyCuaHangThuCungSieuPet" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_M_2147893360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.M!MTB"
        threat_id = "2147893360"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 20 00 01 00 00 5d 17 5b d2}  //weight: 2, accuracy: High
        $x_2_2 = {03 8e 69 17 5b}  //weight: 2, accuracy: High
        $x_2_3 = {03 04 17 58 06 5d 91}  //weight: 2, accuracy: High
        $x_2_4 = {03 04 61 05 59 20 00 01 00 00 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_S_2147893963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.S!MTB"
        threat_id = "2147893963"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 72 13 14 00 70 6f ?? ?? ?? ?? 0b 16 0c 2b 13 00 07 08 07 08 91 20 ?? ?? ?? ?? 59 d2 9c 08 17 58 0c 00 08 07 8e 69 fe 04 0d 09 2d e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_N_2147896706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.N!MTB"
        threat_id = "2147896706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 95 02 3c c9 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 47 00 00 00 16 00 00 00 58 00 00 00 93}  //weight: 2, accuracy: High
        $x_1_2 = "get_IsAttached" ascii //weight: 1
        $x_1_3 = "ParameterizedThreadStart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_O_2147898152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.O!MTB"
        threat_id = "2147898152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 70 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_P_2147902082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.P!MTB"
        threat_id = "2147902082"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 dd a2 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 81 00 00 00 24 00 00 00 ad 00 00 00 7f 01}  //weight: 2, accuracy: High
        $x_1_2 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_Q_2147902183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.Q!MTB"
        threat_id = "2147902183"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {91 61 07 11}  //weight: 2, accuracy: High
        $x_2_2 = {5d 59 d2 9c 11}  //weight: 2, accuracy: High
        $x_1_3 = "ResourceManager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRAT_R_2147918905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRAT.R!MTB"
        threat_id = "2147918905"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 0c 03 16 31 09 03 08 6f ?? 00 00 0a 32 06}  //weight: 2, accuracy: Low
        $x_4_2 = {08 03 17 59 6f ?? 00 00 0a 06 7b ?? 00 00 04 8e 69 58 0d 08 03 6f ?? 00 00 0a 09 59 13 04 06 7b ?? 00 00 04 09 28}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

