rule Backdoor_Python_Cherryquirk_A_2147969448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Python/Cherryquirk.A"
        threat_id = "2147969448"
        type = "Backdoor"
        platform = "Python: Python scripts"
        family = "Cherryquirk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "xor_key = \"$m7*rYpry3\"" ascii //weight: 5
        $x_1_2 = "run_shellcode" ascii //weight: 1
        $x_1_3 = "run_x64_shellcode(url)" ascii //weight: 1
        $x_1_4 = "create_screenshot" ascii //weight: 1
        $x_1_5 = "run_setup_msi" ascii //weight: 1
        $x_1_6 = "get_payload(url)" ascii //weight: 1
        $x_1_7 = "screen_path = os.path.join(cwd, pc_id + \".png\")" ascii //weight: 1
        $x_1_8 = "elif json_data[\"command\"] == \"download\":" ascii //weight: 1
        $x_1_9 = "command = \"whoami && systeminfo && net user \" + os.getenv('username') + \" /dom && nltest /dclist:\"" ascii //weight: 1
        $x_1_10 = "cmd_line = [\"cmd\", \"/C\", f'chcp 65001 > nul && {command}']" ascii //weight: 1
        $x_1_11 = "task_name = \"PythonLauncher-\" + get_randstr" ascii //weight: 1
        $x_1_12 = "Protection Sys: Windows Defender" ascii //weight: 1
        $x_1_13 = "for url in RPC_URL:" ascii //weight: 1
        $x_1_14 = "encrypted_data[i] = data[i] ^ key[i % len(key)]" ascii //weight: 1
        $x_1_15 = {6b 65 72 6e 65 6c 33 32 2e 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 2e 72 65 73 74 79 70 65 20 3d 20 4c 50 56 4f 49 44 [0-8] 6b 65 72 6e 65 6c 33 32 2e 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 2e 61 72 67 74 79 70 65 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

