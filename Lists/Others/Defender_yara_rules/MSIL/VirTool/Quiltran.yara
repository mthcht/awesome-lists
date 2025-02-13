rule VirTool_MSIL_Quiltran_A_2147733866_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Quiltran.A"
        threat_id = "2147733866"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quiltran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\SILENTTRINITY\\SILENTTRINITY" ascii //weight: 1
        $x_1_2 = "<AddPythonLibrariesToSysMetaPath>" ascii //weight: 1
        $x_1_3 = {43 72 65 61 74 65 45 6e 67 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {45 43 44 48 4b 65 79 45 78 63 68 61 6e 67 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 65 74 52 65 73 6f 75 72 63 65 49 6e 5a 69 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {52 75 6e 49 50 59 45 6e 67 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_7 = "Found embedded IPY stdlib : {0}" wide //weight: 1
        $x_1_8 = {61 00 70 00 70 00 65 00 6e 00 64 00 [0-4] 6d 00 65 00 74 00 61 00 5f 00 70 00 61 00 74 00 68 00 [0-4] 70 00 61 00 74 00 68 00}  //weight: 1, accuracy: Low
        $x_1_9 = "resolve assemblies by staging zip" wide //weight: 1
        $x_1_10 = "IronPythonDLL" wide //weight: 1
        $x_1_11 = "Attempting HTTP POST to {0}" wide //weight: 1
        $x_1_12 = {44 00 45 00 42 00 55 00 47 00 [0-4] 4d 00 61 00 69 00 6e 00 2e 00 70 00 79 00 [0-4] 45 00 78 00 65 00 63 00 75 00 74 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Quiltran_B_2147742003_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Quiltran.B"
        threat_id = "2147742003"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quiltran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Main.boo" wide //weight: 1
        $x_1_2 = "Stage.boo" wide //weight: 1
        $x_1_3 = "ST.exe <" wide //weight: 1
        $x_1_4 = "System.Web.Extensions" wide //weight: 1
        $x_1_5 = {53 54 32 53 74 61 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {67 65 74 5f 53 65 72 76 65 72 43 65 72 74 69 66 69 63 61 74 65 56 61 6c 69 64 61 74 69 6f 6e 43 61 6c 6c 62 61 63 6b 00}  //weight: 1, accuracy: High
        $x_1_7 = {42 41 53 45 5f 55 52 4c 00}  //weight: 1, accuracy: High
        $x_1_8 = {47 65 74 52 65 73 6f 75 72 63 65 46 72 6f 6d 5a 69 70 00}  //weight: 1, accuracy: High
        $x_1_9 = {45 43 44 69 66 66 69 65 48 65 6c 6c 6d 61 6e 43 6e 67 50 75 62 6c 69 63 4b 65 79 00}  //weight: 1, accuracy: High
        $x_1_10 = {4c 6f 61 64 00 70 61 79 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_11 = {48 45 58 50 53 4b 00 55 52 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule VirTool_MSIL_Quiltran_D_2147742674_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Quiltran.D"
        threat_id = "2147742674"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quiltran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= STClient(Guid: Guid(argv[0])" ascii //weight: 1
        $x_1_2 = "Thread.Sleep(GetSleepAndJitter())" ascii //weight: 1
        $x_1_3 = "= channel.KeyExchange(encryptedPubKey)" ascii //weight: 1
        $x_1_4 = "\"ReleaseId\"" ascii //weight: 1
        $x_1_5 = "Parameters.Ducky" ascii //weight: 1
        $x_1_6 = "Parameters.Pipeline" ascii //weight: 1
        $x_1_7 = "BooCompiler(" ascii //weight: 1
        $x_1_8 = "bytes_to_send.Length == 81920:" ascii //weight: 1
        $x_1_9 = "cmd == 'CompileAndRun':" ascii //weight: 1
        $x_1_10 = "cmd == 'Jitter':" ascii //weight: 1
        $x_1_11 = "class STJob:" ascii //weight: 1
        $x_1_12 = "= Hex2Binary(value)" ascii //weight: 1
        $x_1_13 = "Guid.NewGuid().ToString(\"n\").Substring(0, 8)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Quiltran_A_2147743366_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Quiltran.A!!Quiltran.gen!A"
        threat_id = "2147743366"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quiltran"
        severity = "Critical"
        info = "Quiltran: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Main.boo" wide //weight: 1
        $x_1_2 = "Stage.boo" wide //weight: 1
        $x_1_3 = "ST.exe <" wide //weight: 1
        $x_1_4 = "System.Web.Extensions" wide //weight: 1
        $x_1_5 = {53 54 32 53 74 61 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {67 65 74 5f 53 65 72 76 65 72 43 65 72 74 69 66 69 63 61 74 65 56 61 6c 69 64 61 74 69 6f 6e 43 61 6c 6c 62 61 63 6b 00}  //weight: 1, accuracy: High
        $x_1_7 = {42 41 53 45 5f 55 52 4c 00}  //weight: 1, accuracy: High
        $x_1_8 = {47 65 74 52 65 73 6f 75 72 63 65 46 72 6f 6d 5a 69 70 00}  //weight: 1, accuracy: High
        $x_1_9 = {45 43 44 69 66 66 69 65 48 65 6c 6c 6d 61 6e 43 6e 67 50 75 62 6c 69 63 4b 65 79 00}  //weight: 1, accuracy: High
        $x_1_10 = {4c 6f 61 64 00 70 61 79 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_11 = {48 45 58 50 53 4b 00 55 52 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule VirTool_MSIL_Quiltran_A_2147743366_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Quiltran.A!!Quiltran.gen!A"
        threat_id = "2147743366"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quiltran"
        severity = "Critical"
        info = "Quiltran: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= STClient(Guid: Guid(argv[0])" ascii //weight: 1
        $x_1_2 = "Thread.Sleep(GetSleepAndJitter())" ascii //weight: 1
        $x_1_3 = "= channel.KeyExchange(encryptedPubKey)" ascii //weight: 1
        $x_1_4 = "\"ReleaseId\"" ascii //weight: 1
        $x_1_5 = "Parameters.Ducky" ascii //weight: 1
        $x_1_6 = "Parameters.Pipeline" ascii //weight: 1
        $x_1_7 = "BooCompiler(" ascii //weight: 1
        $x_1_8 = "bytes_to_send.Length == 81920:" ascii //weight: 1
        $x_1_9 = "cmd == 'CompileAndRun':" ascii //weight: 1
        $x_1_10 = "cmd == 'Jitter':" ascii //weight: 1
        $x_1_11 = "class STJob:" ascii //weight: 1
        $x_1_12 = "= Hex2Binary(value)" ascii //weight: 1
        $x_1_13 = "Guid.NewGuid().ToString(\"n\").Substring(0, 8)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Quiltran_A_2147743366_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Quiltran.A!!Quiltran.gen!A"
        threat_id = "2147743366"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quiltran"
        severity = "Critical"
        info = "Quiltran: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\SILENTTRINITY\\SILENTTRINITY" ascii //weight: 1
        $x_1_2 = "<AddPythonLibrariesToSysMetaPath>" ascii //weight: 1
        $x_1_3 = {43 72 65 61 74 65 45 6e 67 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {45 43 44 48 4b 65 79 45 78 63 68 61 6e 67 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 65 74 52 65 73 6f 75 72 63 65 49 6e 5a 69 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {52 75 6e 49 50 59 45 6e 67 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_7 = "Found embedded IPY stdlib : {0}" wide //weight: 1
        $x_1_8 = {61 00 70 00 70 00 65 00 6e 00 64 00 [0-4] 6d 00 65 00 74 00 61 00 5f 00 70 00 61 00 74 00 68 00 [0-4] 70 00 61 00 74 00 68 00}  //weight: 1, accuracy: Low
        $x_1_9 = "resolve assemblies by staging zip" wide //weight: 1
        $x_1_10 = "IronPythonDLL" wide //weight: 1
        $x_1_11 = "Attempting HTTP POST to {0}" wide //weight: 1
        $x_1_12 = {44 00 45 00 42 00 55 00 47 00 [0-4] 4d 00 61 00 69 00 6e 00 2e 00 70 00 79 00 [0-4] 45 00 78 00 65 00 63 00 75 00 74 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Quiltran_H_2147751405_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Quiltran.H"
        threat_id = "2147751405"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quiltran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Main.boo" ascii //weight: 1
        $x_1_2 = "Stage.boo" ascii //weight: 1
        $x_1_3 = "System.Web.Extensions" ascii //weight: 1
        $x_1_4 = "GUID: {0}" ascii //weight: 1
        $x_1_5 = "PSK: {0}" ascii //weight: 1
        $x_1_6 = "URLS: {0}" ascii //weight: 1
        $x_1_7 = "ST.exe <" ascii //weight: 1
        $x_1_8 = "[-] Attempt #{0}" ascii //weight: 1
        $x_1_9 = "[*] Attempting HTTP POST to {0}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

