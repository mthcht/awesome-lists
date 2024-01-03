#!/usr/bin/env python3

import os
import yaml

# you need to be in the directory yml of https://github.com/LOLBAS-Project/LOLBAS/tree/master/yml
# specify the directory path where the files are located
directory = '.'

# specify the name of the output file
output_file = 'lolbas_extract.csv'

# open the output file for writing
with open(output_file, 'w') as output_file_obj:
    # write the header row to the output file
    output_file_obj.write('command,name,description,usecase,category,mitreid\n')

    # iterate over each file in the directory and its subdirectories
    for root, dirs, files in os.walk(directory):
        for filename in files:
            # process only files with .yml extension
            if filename.endswith('.yml') and filename != 'YML-Template.yml' :
                # open the file and read its contents
                with open(os.path.join(root, filename), 'r') as input_file_obj:
                    file_content = input_file_obj.read()

                    # parse the YAML file into a dictionary
                    yml_dict = yaml.safe_load(file_content)

                    # extract the name from the dictionary
                    name = yml_dict.get('Name', '')

                    # extract all occurrences of the Command field from the dictionary
                    commands = yml_dict.get('Commands', [])

                    # iterate over each occurrence of Command, and write the modified command, name, and additional fields to the output file
                    for command in commands:
                        if isinstance(command, dict) and 'Command' in command:
                            command_text = command['Command']

                            # extract additional fields from the dictionary
                            description = command.get('Description', '')
                            usecase = command.get('Usecase', '')
                            category = command.get('Category', '')
                            mitre_id = command.get('MitreID', '')

                            # write the modified command, name, and additional fields to the output file
                            output_file_obj.write("{},{},{},{},{},{},{}\n".format(command_text.replace(',', '*'), name.replace(',', '.'), description.replace(',', '.'), usecase.replace(',', '.'), category.replace(',', '.'), mitre_id.replace(',', '.'), "https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/{}/{}".format(root.split("/")[-1], filename)))
