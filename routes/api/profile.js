const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');

const Profile = require('../../models/Profile')
const User = require('../../models/User')

const {check,validationResult} = require('express-validator/check');

//@route    GET api/profile/me
//@desc     Get current user profile
//@access   Private
router.get('/me', auth, async (req,res) => {
    try{
        const profile = await Profile.findOne({user: req.user.id}).populate('user',['name','avatar']);

        if(!profile){
            return res.status(400).json({msg: 'There is no profile.'})
        }

        res.send(profile);
    }
    catch(err){
        console.log(err);
        res.status(500).send('Server Error');
    }
});

//@route    POST api/profile/me
//@desc     Create / Update user profile
//@access   Private
router.post('/', [
    auth,
    check('status', 'Status is required').not().isEmpty(),
    check('skills', 'Skills are required').not().isEmpty(),

] ,
async (req,res) => {
    const errors = validationResult(req);

    if(!errors.isEmpty()){
        return res.status(400).json({errors: errors.array()});
    }

    const {
        company,
        website,
        location,
        bio,
        status,
        skills,
        youtube,
        facebook,
        twitter,
        instagram,
        linkedin
    } = req.body;
    
    // Build profile object
    const profileFields = {};

    profileFields.user = req.user.id;
    if(company) profileFields.company = company;
    if(website) profileFields.website = website;
    if(location) profileFields.location = location;
    if(bio) profileFields.bio = bio;
    if(status) profileFields.status = status;
    if(skills){
        profileFields.skills = skills.split(',').map(skill => skill.trim());
    }

    //Build Social object
    profileFields.social = {}

    if(youtube) profileFields.social.youtube = youtube;
    if(twitter) profileFields.social.twitter = twitter;
    if(facebook) profileFields.social.facebook = facebook;
    if(linkedin) profileFields.social.linkedin = linkedin;
    if(instagram) profileFields.social.instagram = instagram;

        try{
            let profile = await Profile.findOne({user:req.user.id})

            //Update Profile
            if(profile){

                profile = await Profile.findOneAndUpdate(
                    {user: req.user.id},
                    {$set: profileFields},
                    {new: true}
                )
                
                return res.json(profile);
            }

            //Create Profile
            profile = new Profile(profileFields)

            await profile.save();

            res.json(profile);
        }
        catch(err){
            console.log(err.message);
            res.status(500).send('Server Error')
        }
})


module.exports = router;