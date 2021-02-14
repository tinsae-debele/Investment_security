

import sys

import hashlib
import uuid
import csv


# the function will test if the subject is allowed to do the request
def testAccess(cap_list, role, objec_access, access_request):
    # get the access list right for the request subject.
    role_capList = cap_list[role][0]
    if objec_access in role_capList:   # check if the subject has the object
        # loop in the access right of the subject
        for list_req in role_capList[objec_access]:
            if list_req == access_request:           # compare each subject with
                # asscess Granted, if the  subjet has the privlage of the request
                return "Access Granted"
        return 'Access Denied'            # access Denied ,  if the
    else:
        return 'Access Denied'  # returns Access Denied if the object doesn't have access to it


def inroleUser(userID, password, role):
    salt = uuid.uuid4().hex                       # generate a salt
    # ashed the salt and the password together
    print(role)
    hashed_password = hashlib.sha512(
        (password + salt).encode('utf-8')).hexdigest()
    passData = userID + ':' + salt + ':' + hashed_password + ':' + role
    with open('passwd.txt', 'a') as file:
        file.write(passData + '\n')


def passWordChecker(passWord, userID):
    count_up = 0
    count_low = 0
    count_spe = 0
    count_num = 0
    upper_flg = False
    lower_flg = False
    spe_flg = False
    num_flg = False
    userID_flg = False
    weak_pwd = True
    upperChoose = "A B C D E F G H I J K L M N O P Q R S T U V W X Y Z".split()
    lowerChoose = "a b c d e f g h i j k l m n o p q r s t u v w x y z".split()
    spe_case = "! @ # $ % ? *".split()
    num_chose = "0 1 2 3 4 5 6 7 8 9".split()
    common_weak_password = ["Password1", "Qwerty123",
                            "Qaz123wsx"]  # sample week password

    if passWord != userID:   # checks Passwords matching the user ID must be prohibited
        userID = True
    for p in common_weak_password:
        if p == passWord:
            weak_pwd = False

    for i in passWord:
        if i in upperChoose:
            count_up = count_up + 1
    if count_up > 0:
        upper_flg = True
    for k in passWord:
        if k in lowerChoose:
            count_low = count_low + 1
    if count_low > 0:
        lower_flg = True
    for l in passWord:
        if l in spe_case:
            count_spe = count_spe + 1
    if count_spe > 0:
        spe_flg = True

    for m in passWord:
        if m in num_chose:
            count_num = count_num + 1
    if count_num > 0:
        num_flg = True

    if num_flg and lower_flg and spe_flg and upper_flg and weak_pwd:
        return True
    else:
        return False


# varify the loging information with the password files.
def loginVar(user, pws, list_cab):
    passwd_info = {}
    list_emp = []
    with open("passwd.txt") as f:
        # read information from the password text
        read = csv.reader(f, delimiter=":", skipinitialspace=True)
        for line in read:
            if line != []:
               passwd_info[line[0]] = line[1:]
    # hash the password with the salt indcated from the files
    hashed_password = hashlib.sha512(
        (pws + passwd_info[user][0]).encode('utf-8')).hexdigest()
    if hashed_password == passwd_info[user][1]:  # compare the new hash with
        print("------------------------------")
        print('*******User Information*********')
        print("------------------------------")
        print(" USER ID: {}    Role : {}"  .format(user,passwd_info[user][2]) )
        printInfo(list_cab,passwd_info[user][2])
        return True
    else:
        return False


def printInfo(cap_list, role):
    print('*********Access rights**********')
    for key, value in cap_list[role][0].items():
        print('{} : {}\n' .format(key,value))
    


def main(argv):

    #problem 1:

    subjects = ["client",                "Premium_client",            "Teller",   "Financial_Advisors",
                "Financial_Planners", "Investment_Analyssts", "Technical_Support", "compliance_office"]  # subject in an object

    Object = ['Account Balance', 'Investments Portflio', 'Financial Advisor contact', 'Investment Analyst contact',
              'private consumer instruments', 'money market instruments', 'derivatives trading', 'interest instruments']  # each sobject in a data

    access_right = [['R', 'R', 'R', 0, 0, 0, 0, 0], ['R', 'RW', 'R', 'R', 0, 0, 0, 0],     # access right data for each subject
                    ['CT', 'CT', 'CT', 'CT', 'CT', 'CT', 'CT', 'CT'], [
                        'R', 'RW', 0, 0, 'R', 0, 0, 0],
                    ['R', 'RW', 0, 0, 'R', 'R', 0, 0], [
                        'R', 'RW', 0,  0, 'R', 'R', 'R', 'R'],
                    ['RQ', 'RQ', 'RQ', 'RQ', 'RQ', 'RQ', 'RQ', 'RQ'], ['R', 'RV', 0, 0, 0, 0, 0, 0]]
    cap_list = {}

    #cap_list ={ subjects[0]: { Object[0]: access_right[0][0]} }

    # looping thought each suject and creating a list of access data for subject
    for sub in range(len(subjects)):
        in_cap = {}
        list_obj = []
        # looping thought the object and assigne the right access right to the subject to the object
        for obj in range(len(Object)):
            #print(f'{subjects[sub]} : {Object[obj]}')
            if access_right[sub][obj] == 'R':
                # assigne the right access right to the subject
                in_cap[Object[obj]] = ["READ"]
            elif access_right[sub][obj] == 'RW':
                # assigne the right access right to the subject
                in_cap[Object[obj]] = ["READ", "WRITE"]
            elif access_right[sub][obj] == "RV":
                # assigne the right access right to the subject
                in_cap[Object[obj]] = ["READ", "VALIDATE"]
            elif access_right[sub][obj] == "RQ":
                # assigne the right access right to the subject
                in_cap[Object[obj]] = ["REQUEST"]
            elif access_right[sub][obj] == "CT":
                in_cap[Object[obj]] = ["ACCESS"]
        list_obj.append(in_cap)    # store the data in the list
        # attache the list of data to the  capblity list
        cap_list[subjects[sub]] = list_obj
    #print(cap_list)

    #print(f'{argv[0]} request  of { argv[1]}  {argv[2]} : {testAccess(cap_list, argv[0], argv[1], argv[2])}')  #out put the result

    while True:

        print("SecVault Investments , Inc. ")
        print("---------------------------")
        print("Please select(type) the serivce")
        print("[inrole]      [login]")
        service = input(":>")
        common_weak_password = []
        logout = False

        if service == 'inrole':
            userID = input('Please Enter userID:')            # request imput
            passwrod = input('Please Enter Password:')
            confirme_password = input('Please Enter confirme passWord:')
            role = input('Please Enter role:')

            if passwrod == confirme_password:  # checks of the conf passwrod is the same as the passwerd
                if(passWordChecker(passwrod, userID)):
                    # call the function that store the information submitted  to password
                    inroleUser(userID, passwrod, role)
                    print('User add successefully')   #
                else:
                    print('ERROR: Please follow the password policy, try again')

        elif service == 'login':  # login service
            print("SecVault Investments , Inc. ")
            print("---------------------------")
            userID = input('Please Enter userID:')
            passWord = input('Please Enter Password:')

            #var_info = loginVar(userID, passWord
            # varify  the userName and password:
            if loginVar(userID, passWord, cap_list):
                while True:
                    logout_req = input("Log Out? [y/n]: ")
                    if(logout_req == 'y' or logout_req == 'Y'):
                        break
            else:
                print("Wrong passord or username, Try again\n")


if __name__ == "__main__":
    main(sys.argv[1:])   # argement to input
