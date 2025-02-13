rule Worm_BAT_Autorun_Z_2147642628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:BAT/Autorun.Z"
        threat_id = "2147642628"
        type = "Worm"
        platform = "BAT: Basic scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 65 74 66 69 6c 65 3d 90 02 20 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 [0-50] 22 25 74 65 6d 70 25 5c 25 66 69 6c 65 25}  //weight: 1, accuracy: Low
        $x_1_3 = {63 6f 70 79 20 25 74 65 6d 70 25 5c 25 66 69 6c 65 25 20 22 25 25 ?? 3a 5c 25 66 69 6c 65 25}  //weight: 1, accuracy: Low
        $x_1_4 = {61 74 74 72 69 62 20 2b 68 20 22 25 25 ?? 3a 5c 41 75 74 6f 52 75 6e 2e 69 6e 66}  //weight: 1, accuracy: Low
        $x_1_5 = "echo open=%file%" ascii //weight: 1
        $x_1_6 = "echo shellexecut=%file%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_BAT_Autorun_AA_2147642635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:BAT/Autorun.AA"
        threat_id = "2147642635"
        type = "Worm"
        platform = "BAT: Basic scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 70 79 20 2f 79 20 25 30 20 ?? 3a 5c [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {65 63 68 6f 20 5b 41 75 74 6f 52 75 6e 5d 20 3e 20 ?? 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66}  //weight: 1, accuracy: Low
        $x_1_3 = {65 63 68 6f 20 73 68 65 6c 6c 65 78 65 63 75 74 65 3d [0-50] 2e 65 78 65 20 3e 3e 20 ?? 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66}  //weight: 1, accuracy: Low
        $x_1_4 = "if exist %~dp0\\autorun.inf start %~dp0" ascii //weight: 1
        $x_1_5 = "\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List\" /v %windir%\\system32\\ftp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_BAT_Autorun_AB_2147642641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:BAT/Autorun.AB"
        threat_id = "2147642641"
        type = "Worm"
        platform = "BAT: Basic scripts"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6f 70 79 20 2f 59 20 25 [0-80] 5c 73 79 73 74 65 6d 33 32 5c [0-48] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "for %%i in (C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Y,Z)" ascii //weight: 1
        $x_1_3 = "Del /F /Q /A %Disk%\\autorun.inf" ascii //weight: 1
        $x_1_4 = {43 6f 70 79 20 2f 59 20 25 6e 61 6d 25 [0-48] 5b 25 52 41 4e 44 4f 4d 25 5d [0-48] 2d 50 69 63 74 75 72 65 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "attrib +r +s +h %nam%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

