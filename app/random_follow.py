
from random import randint, choice

from .models import User

from . import db


def run(user_need):

    all_user = User.query.all()

    for each in all_user[0: user_need]:
        counts = randint(0, 10)  #User.query.count()-1
        for i in range(counts):
            chosen = choice(all_user)
            while each.is_following(chosen):
                chosen = choice(all_user)
            print(chosen.username)
            each.follow(chosen)
        db.session.commit()
        print('%s follows %d friends' % (each.username, counts))


if __name__ == "__main__":
    run()