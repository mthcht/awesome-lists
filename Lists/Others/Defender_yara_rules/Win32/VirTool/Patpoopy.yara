rule VirTool_Win32_Patpoopy_A_2147740949_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Patpoopy.A"
        threat_id = "2147740949"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Patpoopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PupyPackageLoader" ascii //weight: 1
        $x_1_2 = "PupyPackageFinder" ascii //weight: 1
        $x_1_3 = "register_pupyimporter" ascii //weight: 1
        $x_1_4 = "pupy_add_package" ascii //weight: 1
        $x_1_5 = "network.lib.streams.PupySocketStream" ascii //weight: 1
        $x_1_6 = "pupy_credentials" ascii //weight: 1
        $x_1_7 = "pupy.memimporter.ctypes" ascii //weight: 1
        $x_1_8 = "pupy.manager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Patpoopy_A_2147740949_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Patpoopy.A"
        threat_id = "2147740949"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Patpoopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "__pupyimporter_dlls(" ascii //weight: 1
        $x_1_2 = "pupy://(" ascii //weight: 1
        $x_1_3 = "pupyized: {}Re" ascii //weight: 1
        $x_1_4 = "Pupy connected:" ascii //weight: 1
        $x_1_5 = {70 75 70 79 5f 63 72 65 64 65 6e 74 69 61 6c 73 2e 70 79 65 [0-16] 5c 78 30 30 5c 78 30 30 5c 78 30 30 5c 78 30 30}  //weight: 1, accuracy: Low
        $x_1_6 = "github.com/n1nj4sec/pupy" ascii //weight: 1
        $x_1_7 = "pupy-client-{}-{}-debug.log" ascii //weight: 1
        $x_1_8 = "network.lib.streams.PupySocketStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Patpoopy_A_2147740950_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Patpoopy.A!!Patpoopy.gen!A"
        threat_id = "2147740950"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Patpoopy"
        severity = "Critical"
        info = "Patpoopy: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PupyPackageLoader" ascii //weight: 1
        $x_1_2 = "PupyPackageFinder" ascii //weight: 1
        $x_1_3 = "register_pupyimporter" ascii //weight: 1
        $x_1_4 = "pupy_add_package" ascii //weight: 1
        $x_1_5 = "network.lib.streams.PupySocketStream" ascii //weight: 1
        $x_1_6 = "pupy_credentials" ascii //weight: 1
        $x_1_7 = "pupy.memimporter.ctypes" ascii //weight: 1
        $x_1_8 = "pupy.manager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Patpoopy_A_2147740950_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Patpoopy.A!!Patpoopy.gen!A"
        threat_id = "2147740950"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Patpoopy"
        severity = "Critical"
        info = "Patpoopy: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "__pupyimporter_dlls(" ascii //weight: 1
        $x_1_2 = "pupy://(" ascii //weight: 1
        $x_1_3 = "pupyized: {}Re" ascii //weight: 1
        $x_1_4 = "Pupy connected:" ascii //weight: 1
        $x_1_5 = {70 75 70 79 5f 63 72 65 64 65 6e 74 69 61 6c 73 2e 70 79 65 [0-16] 5c 78 30 30 5c 78 30 30 5c 78 30 30 5c 78 30 30}  //weight: 1, accuracy: Low
        $x_1_6 = "github.com/n1nj4sec/pupy" ascii //weight: 1
        $x_1_7 = "pupy-client-{}-{}-debug.log" ascii //weight: 1
        $x_1_8 = "network.lib.streams.PupySocketStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Patpoopy_A_2147740950_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Patpoopy.A!!Patpoopy.gen!A"
        threat_id = "2147740950"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Patpoopy"
        severity = "Critical"
        info = "Patpoopy: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "self.getTaskings(" ascii //weight: 1
        $x_1_2 = "self.processTaskings(" ascii //weight: 1
        $x_1_3 = "self.postResponses(" ascii //weight: 1
        $x_1_4 = "self.agent_config" ascii //weight: 1
        $x_1_5 = "\"Jitter\":" ascii //weight: 1
        $x_1_6 = "\"PayloadUUID\":" ascii //weight: 1
        $x_1_7 = "task[\"task_id\"]" ascii //weight: 1
        $x_1_8 = "file_browser[\"files\"]" ascii //weight: 1
        $x_1_9 = "self.postMessageAndRetrieveResponse(" ascii //weight: 1
        $x_1_10 = ".CreateRemoteThread(" ascii //weight: 1
        $x_1_11 = "passedKilldate(" ascii //weight: 1
        $x_1_12 = "\"ProxyHost\":" ascii //weight: 1
        $x_1_13 = "self.agentSleep()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule VirTool_Win32_Patpoopy_A_2147740950_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Patpoopy.A!!Patpoopy.gen!A"
        threat_id = "2147740950"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Patpoopy"
        severity = "Critical"
        info = "Patpoopy: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PupyPackageLoader" ascii //weight: 1
        $x_1_2 = "PupyPackageFinder" ascii //weight: 1
        $x_1_3 = "Pupy reverse shell rpyc service" ascii //weight: 1
        $x_1_4 = "Builtins utilities for pupy" ascii //weight: 1
        $x_1_5 = "pupyimporter" ascii //weight: 1
        $x_1_6 = "pupy_add_package" ascii //weight: 1
        $x_1_7 = "modules pupy and _memimporter" ascii //weight: 1
        $x_1_8 = "import pupy" ascii //weight: 1
        $x_3_9 = "marshal.loads(zlib.decompress(pupy._get_compressed_library_string()" ascii //weight: 3
        $x_2_10 = "return PupyPackageLoader(fullname, content, extension, is_pkg, selected)" ascii //weight: 2
        $x_2_11 = "pupy_add_package(pkdic)" ascii //weight: 2
        $x_2_12 = "sys.meta_path.append(PupyPackageFinder(modules))" ascii //weight: 2
        $x_2_13 = "please start pupy from either it's exe stub or it's reflective DLL" ascii //weight: 2
        $x_1_14 = {00 67 65 74 5f 63 6f 6e 6e 65 63 74 5f 62 61 63 6b 5f 68 6f 73 74 00}  //weight: 1, accuracy: High
        $x_1_15 = {00 67 65 74 5f 61 72 63 68 00}  //weight: 1, accuracy: High
        $x_1_16 = {00 67 65 74 20 63 75 72 72 65 6e 74 20 70 75 70 79 20 61 72 63 68 69 74 65 63 74 75 72 65 20 28 78 38 36 20 6f 72 20 78 36 34 29 00}  //weight: 1, accuracy: High
        $x_1_17 = "reflective_inject_dll(pid, dll_buffer, isRemoteProcess64bits)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

