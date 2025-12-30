rule VirTool_Win32_Empire_B_2147779284_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Empire.B"
        threat_id = "2147779284"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Empire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "-join[Char[]](& $R $data ($IV+$K))|IEX" ascii //weight: 1
        $x_1_2 = "$_-bxor$s[($s[$i]+$s[$h])%256]}}" ascii //weight: 1
        $x_1_3 = "=[system.text.encoding]::ascii.getbytes('" ascii //weight: 1
        $x_1_4 = {24 00 74 00 3d 00 27 00 2f 00 [0-48] 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = {24 74 3d 27 2f [0-48] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_6 = "$ser+$t" ascii //weight: 1
        $x_1_7 = "Convert]::FromBase64String(" ascii //weight: 1
        $x_1_8 = "%{$J=($J+$S[$_]+$K[$_%$K.Count])%256" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule VirTool_Win32_Empire_A_2147815730_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Empire.A"
        threat_id = "2147815730"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Empire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Start-Negotiate -S" ascii //weight: 1
        $x_1_2 = "$Script:ControlServers[$Script:ServerIndex]" ascii //weight: 1
        $x_1_3 = "(ps|tasklist)" ascii //weight: 1
        $x_1_4 = "$script:AgentJitter" ascii //weight: 1
        $x_1_5 = "[GC]::Collect()" ascii //weight: 1
        $x_1_6 = {20 00 2d 00 62 00 78 00 6f 00 72 00 20 00 24 00 [0-8] 5b 00 28 00 24 00 [0-8] 5b 00 24 00 [0-4] 5d 00 20 00 2b 00 20 00 24 00 [0-8] 5b 00 24 00 [0-4] 5d 00 29 00 20 00 25 00 20 00 32 00 35 00 36 00 5d 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_7 = {20 2d 62 78 6f 72 20 24 [0-8] 5b 28 24 [0-8] 5b 24 [0-4] 5d 20 2b 20 24 [0-8] 5b 24 [0-4] 5d 29 20 25 20 32 35 36 5d 3b}  //weight: 1, accuracy: Low
        $x_1_8 = {2e 00 55 00 70 00 6c 00 6f 00 61 00 64 00 44 00 61 00 74 00 61 00 28 00 24 00 [0-16] 2b 00 22 00 2f 00 [0-64] 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_9 = {2e 55 70 6c 6f 61 64 44 61 74 61 28 24 [0-16] 2b 22 2f [0-64] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_10 = " -PacketData $TaskData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule VirTool_Win32_Empire_A_2147815730_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Empire.A"
        threat_id = "2147815730"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Empire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[System.Net.ServicePointManager]::Expect100Continue=0;" ascii //weight: 1
        $x_1_2 = "=New-Object System.Net.WebClient;" ascii //weight: 1
        $x_1_3 = ".Headers.Add('User-Agent',$" ascii //weight: 1
        $x_1_4 = ".Headers.Add(\"Cookie\",\"" ascii //weight: 1
        $x_1_5 = ".Proxy=[System.Net.WebRequest]::DefaultWebProxy;" ascii //weight: 1
        $x_1_6 = "$Script:Proxy" ascii //weight: 1
        $x_1_7 = "=[System.Text.Encoding]::ASCII.GetBytes('" ascii //weight: 1
        $x_1_8 = "$_-bxor$S[($S[$I]+$S[$H])%256]}}" ascii //weight: 1
        $x_1_9 = ".DownloadData($ser+$t);" ascii //weight: 1
        $x_1_10 = {24 00 74 00 3d 00 27 00 2f 00 [0-48] 2e 00 70 00 68 00 70 00 27 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_11 = {24 74 3d 27 2f [0-48] 2e 70 68 70 27 3b}  //weight: 1, accuracy: Low
        $x_1_12 = "-join[Char[]](& $R $data ($IV+$K))|IEX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

rule VirTool_Win32_Empire_A_2147815730_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Empire.A"
        threat_id = "2147815730"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Empire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Start-Negotiate" ascii //weight: 1
        $x_1_2 = " -StagingKey" ascii //weight: 1
        $x_1_3 = " -SessionKey" ascii //weight: 1
        $x_1_4 = "@(0x01,0x02,0x00,0x00)" ascii //weight: 1
        $x_1_5 = "@(0x01,0x03,0x00,0x00)" ascii //weight: 1
        $x_1_6 = ".Headers.Add(\"User-Agent\"" ascii //weight: 1
        $x_1_7 = "Invoke-Empire -Servers @(" ascii //weight: 1
        $x_1_8 = {20 00 2d 00 62 00 78 00 6f 00 72 00 20 00 24 00 [0-8] 5b 00 28 00 24 00 [0-8] 5b 00 24 00 [0-4] 5d 00 20 00 2b 00 20 00 24 00 [0-8] 5b 00 24 00 [0-4] 5d 00 29 00 20 00 25 00 20 00 32 00 35 00 36 00 5d 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_9 = {20 2d 62 78 6f 72 20 24 [0-8] 5b 28 24 [0-8] 5b 24 [0-4] 5d 20 2b 20 24 [0-8] 5b 24 [0-4] 5d 29 20 25 20 32 35 36 5d 3b}  //weight: 1, accuracy: Low
        $x_1_10 = {5b 00 47 00 43 00 5d 00 3a 00 3a 00 43 00 6f 00 6c 00 6c 00 65 00 63 00 74 00 28 00 29 00 3b 00 [0-32] 20 00 2d 00 53 00 65 00 72 00 76 00 65 00 72 00 73 00 20 00 40 00 28 00}  //weight: 1, accuracy: Low
        $x_1_11 = {5b 47 43 5d 3a 3a 43 6f 6c 6c 65 63 74 28 29 3b [0-32] 20 2d 53 65 72 76 65 72 73 20 40 28}  //weight: 1, accuracy: Low
        $x_1_12 = {2e 00 55 00 70 00 6c 00 6f 00 61 00 64 00 44 00 61 00 74 00 61 00 28 00 24 00 [0-16] 2b 00 22 00 2f 00 [0-64] 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_13 = {2e 55 70 6c 6f 61 64 44 61 74 61 28 24 [0-16] 2b 22 2f [0-64] 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule VirTool_Win32_Empire_C_2147960256_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Empire.C"
        threat_id = "2147960256"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Empire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Invoke-Empire -Servers @(" ascii //weight: 1
        $x_1_2 = ".Headers.Add(\"User-Agent\"" ascii //weight: 1
        $x_1_3 = "[GC]::Collect()" ascii //weight: 1
        $x_1_4 = "(ps|tasklist)" ascii //weight: 1
        $x_1_5 = "$Script:ControlServers[$Script:ServerIndex]" ascii //weight: 1
        $x_1_6 = "Start-Negotiate -S" ascii //weight: 1
        $x_1_7 = " -StagingKey" ascii //weight: 1
        $x_1_8 = "$script:AgentJitter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Empire_D_2147960257_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Empire.D"
        threat_id = "2147960257"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Empire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".DownloadData($ser+$t);" ascii //weight: 1
        $x_1_2 = "=[System.Text.Encoding]::ASCII.GetBytes('" ascii //weight: 1
        $x_1_3 = {24 00 74 00 3d 00 27 00 2f 00 [0-48] 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = {24 74 3d 27 2f [0-48] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_5 = ".Proxy=[System.Net.WebRequest]::DefaultWebProxy;" ascii //weight: 1
        $x_1_6 = "$Script:Proxy" ascii //weight: 1
        $x_1_7 = ".Headers.Add('User-Agent',$" ascii //weight: 1
        $x_1_8 = ".Headers.Add(\"Cookie\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

