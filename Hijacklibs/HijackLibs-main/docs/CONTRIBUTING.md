# How to contribute to the HijackLibs project

🎉 First off, thanks for taking the time to contribute!


## New entry

You found or read about a new DLL Hijacking opportunity, good stuff! 

<details><summary>Click here to find out how to contribute</summary>
<p>

By creating a YAML file that follows our schema[^1], you can get your suggestion added to this project very easily.

0. **Before you start**: 
   make sure there isn't already an entry for the DLL you want to add!

1. **Fork and clone this project**
   If you're not familiar with this, you can find more information on how to do this via [GitHub Docs](https://docs.github.com/en/get-started/quickstart/fork-a-repo).

2. **Create a new YAML file**
   Create a new `.yml` file under the `/yml` folder. Use the name of the DLL file you will be documenting as the name of the file, all lower case.
   For example, if you want to create an entry for `LorumIpsum.dll`, call your file `lorumipsum.yml`. 

3. **Follow this project's schema**
   Copy this project's [template](/template.yml) and paste it in your newly created file. Now populate all fields where possible; remove any fields you don't need, and please remove all comments before proceeding to the next step.

5. **Push and check GitHub actions**
   Push your entry to your own fork (see [GitHub Docs](https://docs.github.com/en/get-started/using-git/pushing-commits-to-a-remote-repository)). A couple of checks will be performed by GitHub actions, to check if your contribution is passing our quality checks. Putting it simply, it is checking if the file you created is valid YAML and whether the fields have been populated correctly in the expected format[^1].

   If all is well, you should see a green tick (✔️) next to your commit. 
   If a check failed, click the red cross (❌) to get more details on what went wrong. Make sure you fix any issues before proceeding to the next step!
   
5. **Submit your pull request**
   Now all you have to do is open a pull request. 
   One of the maintainers of this project will review your suggestion. If all goes well, your entry will be merged into the the project!

</p>
</details><br />

## Updating an existing entry
You want to improve or extend an existing DLL Hijacking entry, yay!

<details><summary>Click here to find out how to contribute</summary>
<p>

Simply updating the existing YAML file with your new insights will do the job.

1. **Fork and clone this project**
   If you're not familiar with this, you can find more information on how to do this via [GitHub Docs](https://docs.github.com/en/get-started/quickstart/fork-a-repo).

2. **Locate and update the YAML file**
   Locate the `.yml` file under the `/yml` folder and start making changes. Make sure you keep adhering to the YAML schema[^1].

3. **Push and check GitHub actions**
   Push your entry to your own fork (see [GitHub Docs](https://docs.github.com/en/get-started/using-git/pushing-commits-to-a-remote-repository)). A couple of checks will be performed by GitHub actions, to check if your contribution is passing our quality checks. Putting it simply, it is checking if the file you updated is still valid YAML and whether the fields have been populated correctly in the expected format[^1].

   If all is well, you should see a green tick (✔️) next to your commit. 
   If a check failed, click the red cross (❌) to get more details on what went wrong. Make sure you fix any issues before proceeding to the next step!
   
4. **Submit your pull request**
   Now all you have to do is open a pull request. 
   One of the maintainers of this project will review your suggestion. If all goes well, your entry will be merged into the the project!

</p>
</details><br />

## Website updates
You want to make the website even better, whoohoo!
<details><summary>Click here to find out how to contribute</summary>
<p>

The website is hosted in GitHub pages and uses Jekyll. You can find the code of the website in the `gh-pages` branch.

1. **Fork and clone this project**
   If you're not familiar with this, you can find more information on how to do this via [GitHub Docs](https://docs.github.com/en/get-started/quickstart/fork-a-repo).

2. **Check out the `gh-pages` branch**
   Make sure you are on the right branch before making any changes. 

3. **Make your changes**
   Update the required files to make the changes you want to make. Remember that you can get a local instance of the website running via Jekyll (see [GitHub Docs](https://docs.github.com/en/pages/setting-up-a-github-pages-site-with-jekyll/testing-your-github-pages-site-locally-with-jekyll)) to validate the changes you have made.

4. **Push and check GitHub actions**
   Push your entry to your own fork (see [GitHub Docs](https://docs.github.com/en/get-started/using-git/pushing-commits-to-a-remote-repository)).   
5. **Submit your pull request**
   Now all you have to do is open a pull request. 
   One of the maintainers of this project will review your suggestion. If all goes well, your entry will be merged into the the project! 
</p>
</details><br />

## Anything else
Do you want to contribute in a way that's not covered by the above? Please feel free to open an issue on GitHub and we'll look into it - all suggestions are welcome.

[^1]: Our YAML schema defines what fields are expected, what types they have, what format string should be in, and whether or not they are required. You can find a human-readable version of this schema [here](SCHEMA.md).
