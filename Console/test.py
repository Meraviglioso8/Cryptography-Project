password = 'm3r@pass'
hash_riu='$argon2id$v=19$m=65536,t=3,p=4$N7QW8GVrOEgLsgqAesTeMA$F2/wcbIFhnEE3uWAJjRU8wefWBaWvxm/tQOQiq1I1H0'
pass_fake='mrta'

from argon2 import PasswordHasher


ph = PasswordHasher()
output = ph.verify(hash_riu,password)
print(output)