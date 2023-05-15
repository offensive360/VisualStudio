# Offensive 360 for Visual Studio

Offensive 360 does deep source code analysis with one click. (We spent years building virtual compilers that understand the code, not only catching low hanging fruits vulnerabilities. We also claim that O360 can find security flaws that are even difficult for skilled application security testing consultants to find)

This section explains how to install and configure the Offensive 360 Visual Studio Extension Plugin and how to scan files, folder and workspace.

## Installing the Plugin

1. Open the Microsoft Visual Studio application, navigate to the Extensions and click on Manage Extensions. 
![image](https://user-images.githubusercontent.com/13881466/179386371-b154f676-b3cb-40f9-a2a3-ccc4c087b61f.png)

2. Search for **Offensive 360** and click on download
![image](https://user-images.githubusercontent.com/13881466/179388357-3882e518-45f9-429d-a2e8-da54cd1a264c.png)


## Configuring Offensive 360 Settings
1. Click on `Tools menu => Options => Settings` to configure Offensive 360 settings if you are installing for first time or if you want to make any change to existing Offensive 360 settings.
![image](https://user-images.githubusercontent.com/13881466/179386601-35c68339-347d-4711-9a01-a4507eac1cae.png)

2. Then expend `Offensive360` node from left menu bar and click on `General`
![image](https://user-images.githubusercontent.com/13881466/179386662-3589e4e4-fd5e-4382-8388-92b5f71c214b.png)

3. Enter Offensive 360 scan endpoint and access token information and click on ok button

## How it works
1. Simply open any .Net solution in Visual studio and click on `Build => Offensive 2360 : Scan` menu to start the scaning of current .Net solution 
![image](https://user-images.githubusercontent.com/13881466/179387100-c090d853-8db9-476a-8f08-7a26357c29cb.png)

2. You will see queued status on status bar that indicates you scan request got queued.
![image](https://user-images.githubusercontent.com/13881466/179387177-2b6bb39d-ba0b-4ff2-8eb5-bbe69489e85e.png)

 3. After some time message on status bar will be updated to let you know whether your scan request is still in queued state or it reached to in-progress state. if it is still in queued, you will see queue position.
 ![image](https://user-images.githubusercontent.com/13881466/179387190-08938922-a450-4871-9f7b-a4148dfb2a5b.png)
  ![image](https://user-images.githubusercontent.com/13881466/183275900-5703822e-7c8f-455e-ba6d-15e6b1f7bc40.png)

4. As soon as scanning is done, you will see vulnerabilities in IDE
![image](https://user-images.githubusercontent.com/13881466/179387216-06a2cbde-2d2a-493e-8a1f-8b086de47071.png)

5. By clicking on a vulnerability, you will be redirected to respective code file, line and column.
![image](https://user-images.githubusercontent.com/13881466/179387234-8849d8c0-0d4f-4bf7-9faf-264cb0397173.png)

6. `Clear all Errors` on right click on a vulnerability will be appeared and help you in clearing all the errors from IDE
![image](https://user-images.githubusercontent.com/13881466/179387272-f8d02436-5166-42fe-8de5-685d64b49311.png)
![image](https://user-images.githubusercontent.com/13881466/179387304-b898131a-30a6-4ebe-ab5f-d4489a022850.png)

7. `Get Help` on right click on a vulnerability will be appeared and help you in getting more details about a vulnerability
![image](https://user-images.githubusercontent.com/13881466/179387293-df2777ec-95ee-4947-8f31-410b87b61cd9.png)

**Enjoy!!**
