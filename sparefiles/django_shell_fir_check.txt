from users.models import FIR

# To get all FIRs
all_firs = FIR.objects.all()
for fir in all_firs:
    print(fir)

# To get FIRs of a specific user (replace 'user_id' with the actual user id)
user_id = 1  # Example user ID
user_firs = FIR.objects.filter(user_id=user_id)
for fir in user_firs:
    print(fir)

# To count the number of FIRs
fir_count = FIR.objects.count()
print(f"Total number of FIRs: {fir_count}")

# To get FIRs of a specific crime type
crime_type = 'Cyber'  # Example crime type
crime_firs = FIR.objects.filter(crime_type=crime_type)
for fir in crime_firs:
    print(fir)
