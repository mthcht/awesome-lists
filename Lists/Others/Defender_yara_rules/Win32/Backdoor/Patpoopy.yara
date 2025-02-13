rule Backdoor_Win32_Patpoopy_A_2147706520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Patpoopy.A"
        threat_id = "2147706520"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Patpoopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
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

rule Backdoor_Win32_Patpoopy_A_2147706520_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Patpoopy.A"
        threat_id = "2147706520"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Patpoopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 70 75 70 79 78 36 34 2e 64 6c 6c 00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00}  //weight: 5, accuracy: High
        $x_5_2 = {00 70 75 70 79 78 36 34 2e 75 6e 63 2e 64 6c 6c 00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00}  //weight: 5, accuracy: High
        $x_5_3 = {00 70 75 70 79 78 38 36 2e 64 6c 6c 00 5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 34 00}  //weight: 5, accuracy: High
        $x_5_4 = {00 70 75 70 79 78 38 36 2e 75 6e 63 2e 64 6c 6c 00 5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 34 00}  //weight: 5, accuracy: High
        $x_2_5 = "get current pupy architecture (x86 or x64)" ascii //weight: 2
        $x_2_6 = "get_pupy_config" ascii //weight: 2
        $x_2_7 = {00 70 75 70 79 2e 65 72 72 6f 72 00}  //weight: 2, accuracy: High
        $x_2_8 = "Builtins utilities for pupy" ascii //weight: 2
        $x_2_9 = "####---PUPY_CONFIG_COMES_HERE---####" ascii //weight: 2
        $x_1_10 = "/n1nj4sec/" ascii //weight: 1
        $x_1_11 = "@n1nj4sec" ascii //weight: 1
        $x_1_12 = "contact@n1nj4.eu" ascii //weight: 1
        $x_1_13 = "\\pupy\\network\\lib\\" ascii //weight: 1
        $x_1_14 = "BasePupyTransport" ascii //weight: 1
        $x_1_15 = "DummyPupy" ascii //weight: 1
        $x_1_16 = "from network.lib.streams.PupySocketStream import PupyChannel" ascii //weight: 1
        $x_1_17 = "from pupy_credentials import BIND_PAYLOADS_PASSWORD" ascii //weight: 1
        $x_1_18 = "mod = imp.new_module(\"pupy\")" ascii //weight: 1
        $x_1_19 = "mod.__file__ = \"pupy://pupy\"" ascii //weight: 1
        $x_1_20 = "mod.__package__ = \"pupy\"" ascii //weight: 1
        $x_1_21 = "Pupy reverse shell rpyc service" ascii //weight: 1
        $x_1_22 = "pupy.get_connect_back_host = (lambda: HOST)" ascii //weight: 1
        $x_1_23 = "pupy.infos = {}" ascii //weight: 1
        $x_1_24 = "pupy://{}" ascii //weight: 1
        $x_1_25 = "pupy_srv" ascii //weight: 1
        $x_1_26 = "PupyAsync" ascii //weight: 1
        $x_1_27 = "PupyCDLL._find_function_address: {} = {}" ascii //weight: 1
        $x_1_28 = "PupyConnection" ascii //weight: 1
        $x_1_29 = "PupyHTTP" ascii //weight: 1
        $x_1_30 = "pupylib.PupyCredentials" ascii //weight: 1
        $x_1_31 = "PupyPackageLoader:" ascii //weight: 1
        $x_1_32 = "PupyProxified" ascii //weight: 1
        $x_1_33 = "PupySocketStream" ascii //weight: 1
        $x_1_34 = "PupySSLClient" ascii //weight: 1
        $x_1_35 = "PupyTCP" ascii //weight: 1
        $x_1_36 = "PupyUDP" ascii //weight: 1
        $x_1_37 = "PupyWebSocket" ascii //weight: 1
        $x_1_38 = "remote_print_error = pupyimporter.remote_print_error" ascii //weight: 1
        $x_1_39 = "setattr(pupy, 'Task', Task)" ascii //weight: 1
        $x_1_40 = "sys.modules[\"pupy\"] = mod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

