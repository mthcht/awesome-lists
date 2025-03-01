rule Trojan_MSIL_AveMariaRat_ME_2147810509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRat.ME!MTB"
        threat_id = "2147810509"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-enc aQBwAGMAbwBu" wide //weight: 1
        $x_1_2 = "proxy" ascii //weight: 1
        $x_1_3 = "ToString" ascii //weight: 1
        $x_1_4 = "Base64Encoder" ascii //weight: 1
        $x_1_5 = "Hidden" ascii //weight: 1
        $x_1_6 = "get_Key" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "CodeAccessPermission" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRat_MG_2147811767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRat.MG!MTB"
        threat_id = "2147811767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateDomain" ascii //weight: 1
        $x_1_2 = "wwrr" wide //weight: 1
        $x_1_3 = "s3vJRJVbYmADYLexQv" wide //weight: 1
        $x_1_4 = "BlackMarket" ascii //weight: 1
        $x_1_5 = "restart" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "PaymentForm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRat_MF_2147811904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRat.MF!MTB"
        threat_id = "2147811904"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 34 00 37 00 32 00 30 00 35 00 31 00 32 00 33 00 32 00 30 00 31 00 34 00 35 00 39 00 38 00 31 00 34 00 34 00 2f 00 [0-96] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "/C timeout" wide //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "MagicLine4NX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRat_ML_2147812732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRat.ML!MTB"
        threat_id = "2147812732"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Reverse" ascii //weight: 1
        $x_1_2 = "tiny.one/adam02045dam2" wide //weight: 1
        $x_1_3 = "PatchThread" ascii //weight: 1
        $x_1_4 = "Test-Connection" wide //weight: 1
        $x_1_5 = "Rpptgdcnwaszmuxvfq" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRat_MN_2147812734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRat.MN!MTB"
        threat_id = "2147812734"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0d 2b 1a 00 07 1f 00 28 ?? ?? ?? 0a 0a 20 00 58 00 00 8d 46 00 00 01 [0-9] 09 06 09 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 00 09 17 58 0d 09 20 00 58 00 00 fe 04 13 04 11 04 2d}  //weight: 1, accuracy: Low
        $x_1_2 = "ToString" ascii //weight: 1
        $x_1_3 = "GetPlacedGemsString" ascii //weight: 1
        $x_1_4 = "Welcome to Ghost Party" wide //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
        $x_1_6 = "Bcellerm03" ascii //weight: 1
        $x_1_7 = "Debug" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRat_MR_2147815335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRat.MR!MTB"
        threat_id = "2147815335"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Decrypt" ascii //weight: 1
        $x_1_2 = "isVirtualMachine" ascii //weight: 1
        $x_1_3 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_4 = "newMutex" ascii //weight: 1
        $x_1_5 = "OZavQr3Za2A4vecg6h6pIg==" wide //weight: 1
        $x_1_6 = "DynamicDllInvokeType" wide //weight: 1
        $x_1_7 = "EncryptionKey" ascii //weight: 1
        $x_1_8 = "fgsdaaaaaaaaaaagsdgs" ascii //weight: 1
        $x_1_9 = "CreateDecryptor" ascii //weight: 1
        $x_1_10 = "Debugger" ascii //weight: 1
        $x_1_11 = "Sleep" ascii //weight: 1
        $x_1_12 = "MemoryStream" ascii //weight: 1
        $x_1_13 = "TransformFinalBlock" ascii //weight: 1
        $x_1_14 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRat_2147819021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRat.MT!MTB"
        threat_id = "2147819021"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "scvhost.exe" wide //weight: 10
        $x_1_2 = "ssddfdasdffffffffffffffffffddd" wide //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "DebuggerLaunched" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "TransformFinalBlock" ascii //weight: 1
        $x_1_8 = "CreateDecryptor" ascii //weight: 1
        $x_1_9 = "GetBytes" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRat_YIVF_2147819902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRat.YIVF!MTB"
        threat_id = "2147819902"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 8e 69 5d 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 0a 03 08 18 58 17 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRat_MX_2147822275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRat.MX!MTB"
        threat_id = "2147822275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 16 07 22 00 06 6f 22 00 00 0a 00 00 de 05 26 00 00 de 00 72 29 00 00 70 28 05 00 00 06 [0-6] 8e 69 28 23 00 00 0a 00 07 0c 2b 00 08 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "Santa" ascii //weight: 1
        $x_1_3 = "GetTeacher" ascii //weight: 1
        $x_1_4 = "DynamicInvoke" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRat_MW_2147823655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRat.MW!MTB"
        threat_id = "2147823655"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Phwsmnvrxxdsdqrtjdqfvdb" ascii //weight: 10
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "DynamicInvoke" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "ReadBytes" ascii //weight: 1
        $x_1_6 = "://2.58.149.2/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRat_MY_2147825199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRat.MY!MTB"
        threat_id = "2147825199"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 07 2b 03 00 2b 07 6f ?? ?? ?? 0a 2b f6 00 de 11 08 2b 08 08 6f ?? ?? ?? 0a 2b 04 2c 03 2b f4 00 dc 07 6f ?? ?? ?? 0a 0d de 1c}  //weight: 1, accuracy: Low
        $x_1_2 = "MemoryStream" ascii //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
        $x_1_4 = "DynamicInvoke" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "ThreadWasSuspended" ascii //weight: 1
        $x_1_7 = "DebuggerInactive" ascii //weight: 1
        $x_1_8 = "TransformFinalBlock" ascii //weight: 1
        $x_1_9 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRat_MU_2147901448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRat.MU!MTB"
        threat_id = "2147901448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InvokeMember" ascii //weight: 1
        $x_1_2 = "Upmrsiatbczppndauayjdra" wide //weight: 1
        $x_1_3 = "DeleteIssuer" ascii //weight: 1
        $x_1_4 = "://2.56.56.114/" wide //weight: 1
        $x_1_5 = "RestartIssuer" ascii //weight: 1
        $x_1_6 = "ToArray" ascii //weight: 1
        $x_1_7 = "MemoryStream" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMariaRat_MC_2147901835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMariaRat.MC!MTB"
        threat_id = "2147901835"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AZd2335678" ascii //weight: 1
        $x_1_2 = "IMDBClone\\obj\\Debug\\Kwna.pdb" ascii //weight: 1
        $x_1_3 = "s://cdn.disc" wide //weight: 1
        $x_1_4 = "ordapp.com" wide //weight: 1
        $x_1_5 = {2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 39 00 31 00 31 00 39 00 30 00 37 00 31 00 33 00 36 00 30 00 34 00 37 00 35 00 35 00 34 00 35 00 36 00 33 00 2f 00 [0-48] 2f 00 36 00 30 00 30 00}  //weight: 1, accuracy: Low
        $x_1_6 = "Concat" ascii //weight: 1
        $x_1_7 = "DownloadData" ascii //weight: 1
        $x_1_8 = "CreateFile" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "set_Size" ascii //weight: 1
        $x_1_11 = "ToString" ascii //weight: 1
        $x_1_12 = "m_textBox_password_Click" ascii //weight: 1
        $x_1_13 = "set_PasswordChar" ascii //weight: 1
        $x_1_14 = "select cookie_id,count(*) from cookie" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

