rule VirTool_Win32_Meterpreter_A_2147754324_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Meterpreter.gen!A"
        threat_id = "2147754324"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MeterpreterProcess(MeterpreterChannel)" ascii //weight: 1
        $x_1_2 = "super(MeterpreterSocketUDPClient" ascii //weight: 1
        $x_1_3 = "PythonMeterpreter(transport)" ascii //weight: 1
        $x_1_4 = "add_channel(MeterpreterSocketTCPClient" ascii //weight: 1
        $x_1_5 = "xor_bytes(xor_key" ascii //weight: 1
        $x_1_6 = "runcode(compile" ascii //weight: 1
        $x_1_7 = "_try_to_fork" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Meterpreter_A_2147754325_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Meterpreter.gen!A!!Meterpreter.gen!A"
        threat_id = "2147754325"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MeterpreterProcess(MeterpreterChannel)" ascii //weight: 1
        $x_1_2 = "super(MeterpreterSocketUDPClient" ascii //weight: 1
        $x_1_3 = "PythonMeterpreter(transport)" ascii //weight: 1
        $x_1_4 = "add_channel(MeterpreterSocketTCPClient" ascii //weight: 1
        $x_1_5 = "xor_bytes(xor_key" ascii //weight: 1
        $x_1_6 = "runcode(compile" ascii //weight: 1
        $x_1_7 = "_try_to_fork" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Meterpreter_2147765144_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Meterpreter"
        threat_id = "2147765144"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = {48 31 c9 41 ba 45 83 56 07 ff d5 48 31 c9 41 ba f0 b5 a2 56 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Meterpreter_J_2147844471_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Meterpreter.J!MTB"
        threat_id = "2147844471"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0e 20 85 c0 84 84 46 02 00 00 6a 99 ff ?? 83 c4 3d 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 04 01 c0 d0 13 8b 4d 10 8b ca 8c 50 51 52}  //weight: 1, accuracy: High
        $x_1_3 = {21 43 50 a4 f8 73 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

