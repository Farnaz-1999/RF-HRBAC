# RF_HRBAC
RF_HRBAC is an access control model for IoT-based systems, especially healthcare systems.

* Create Envirenment:
  >python3 -m venv RF_HRBAC


* Activate Enviernment:

  (in MacOS):  
    >source RF_HRBAC/bin/activate
  
  (in Windows):
    >.\RF_HRBAC\Scripts\bin\activate


* Install Requierments:
  >pip install -r requirements.txt


* Run Server after editing the .env file variables and generating a basic db:
  >cd server

  >python -m uvicorn main:app --reload

  
in tests directory test.py is available with a method that you can use to test the model.

